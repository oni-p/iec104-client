#![forbid(unsafe_code)]

use std::io::{ Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const RTU_ADDR: &str = "192.168.11.93:2404";

// ================= Kebijakan Operasi =================
// Kirim STARTDT act satu kali di awal? (umumnya perlu agar RTU mulai kirim data)
const SEND_STARTDT_ONCE: bool = true;
// Mode ACK-only: TIDAK ADA I-frame keluar.
const ACK_ONLY: bool = true;
// Nonaktifkan TESTFR saat idle (ACK-only murni)
const SEND_TESTFR_WHEN_IDLE: bool = false;

// ================= Parameter Siemens (umum) =================
const SIEMENS_K: u16 = 12;                     // jendela kirim sisi RTU (perkiraan)
const SIEMENS_W: usize = 8;                    // wajib ACK setelah 8 I-frame diterima
const T2: Duration = Duration::from_secs(10);  // timeout t2 untuk ACK koalescing

// ================= Konstanta U-frame =================
const U_STARTDT_ACT: u8 = 0x07;
const U_STARTDT_CON: u8 = 0x0B;
const U_STOPDT_ACT:  u8 = 0x13;
const U_STOPDT_CON:  u8 = 0x23;
const U_TESTFR_ACT:  u8 = 0x43;
const U_TESTFR_CON:  u8 = 0x83;

// ================= Larangan tipe ASDU keluar =================
const FORBIDDEN_TYPE_IDS: &[u8] = &[45, 46]; // C_SC_NA_1, C_DC_NA_1

struct AckStats { w: u64, t2: u64, emergency: u64 }
impl AckStats {
    fn inc(&mut self, reason: &str) {
        match reason { "w" => self.w+=1, "t2" => self.t2+=1, "emergency" => self.emergency+=1, _=>{} }
    }
}

fn main() -> std::io::Result<()> {
    println!("IEC 60870-5-104 Client/Master (ACK-only; Siemens w/t2; anti-45/46)");
    println!("Menghubungkan ke RTU {} ...", RTU_ADDR);
    let mut stream = TcpStream::connect(RTU_ADDR)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_nodelay(true)?;
    let mut ack_stats = AckStats { w:0, t2:0, emergency:0 };
    // Gatekeeper untuk semua TX
    let mut tx = TxPolicy::new();

    // STARTDT act sekali (opsional)
    if SEND_STARTDT_ONCE {
        tx.send_startdt(&mut stream)?;
    } else {
        println!("(Info) STARTDT act dimatikan; banyak RTU tidak kirim data tanpa ini.");
    }

    // Buffer penerimaan & state parsing
    let mut rx_buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

    // State ACK koalescing (Siemens w/t2)
    let mut since_last_ack = 0usize;
    let mut t2_started: Option<Instant> = None;

    // State sequence / window
    let mut last_ack_nr: u16 = 0; // N(R) terakhir yang sudah dikirim
    let mut next_nr: u16 = 0;     // N(R) kandidat untuk ACK berikutnya

    // Untuk (opsional) TESTFR saat idle — default dinonaktifkan
    let mut last_read = Instant::now();

    // Baca terus sampai koneksi putus.
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => {
                println!("Koneksi ditutup oleh peer.");
                break;
            }
            Ok(n) => {
                last_read = Instant::now();
                rx_buf.extend_from_slice(&tmp[..n]);

                // Proses semua APDU utuh yang ada di buffer
                while let Some((apdu, consumed)) = take_one_apdu(&rx_buf) {
                    // Tampilkan hex mentahnya
                    println!("< RX {} bytes: {}", apdu.len(), hex(apdu));

                    // Klasifikasikan & tampilkan ringkasan
                    match classify_apdu(apdu) {
                        Frame::U(ut) => {
                            println!("  ▸ Frame: U-Frame ({})", ut);
                            if ut == UType::StartDtCon {
                                println!("  ▸ STARTDT dikonfirmasi RTU. Data dapat mulai mengalir.");
                            }
                        }
                        Frame::S { nr } => {
                            println!("  ▸ Frame: S-Frame (ACK) | N(R)={}", nr);
                        }
                        Frame::I { ns, nr, asdu } => {
                            println!("  ▸ Frame: I-Frame | N(S)={} N(R)={}", ns, nr);
                            if let Some(a) = asdu {
                                println!(
                                    "    ASDU: type_id={}{} vsq=0x{:02X} cot={} casdu={} ioa_first={}",
                                    a.type_id,
                                    asdu_type_name(a.type_id).map(|n| format!(" ({})", n)).unwrap_or_default(),
                                    a.vsq, a.cot, a.casdu, a.ioa_first
                                );
                            } else {
                                println!("    ASDU: (tidak utuh/pendek)");
                            }

                            // Update koalescing dan jendela
                            next_nr = seq_inc(ns);                  // ACK untuk frame ini => ns+1 (mod 32768)
                            since_last_ack += 1;
                            if t2_started.is_none() { t2_started = Some(Instant::now()); }

                            // Hitung jendela terpakai di sisi pengirim (RTU)
                            let used = seq_distance(next_nr, last_ack_nr);
                            println!(
                                "    window_used ≈ {}/{} ({}%)",
                                used,
                                SIEMENS_K,
                                ((used as f32 / SIEMENS_K as f32) * 100.0).round() as u32
                            );

                            // Keputusan ACK:
                            let emergency = used >= SIEMENS_K.saturating_sub(2); // hampir mentok k
                            let need_by_count = since_last_ack >= SIEMENS_W;     // capai w
                            let need_by_t2 = t2_started.map(|s| s.elapsed() >= T2).unwrap_or(false);

                            if emergency || need_by_count || need_by_t2 {
                                let reason = if emergency { "emergency" } else if need_by_count { "w" } else { "t2" };
                                tx.send_s_ack(&mut stream, next_nr, reason)?;
                                ack_stats.inc(reason);
                                println!("    ack_stats: w={} t2={} emergency={}", ack_stats.w, ack_stats.t2, ack_stats.emergency);
   
                                last_ack_nr = next_nr;
                                since_last_ack = 0;
                                t2_started = None;
                            }
                        }
                        Frame::Unknown => {
                            println!("  ▸ Frame: (tidak dikenali)");
                        }
                    }

                    // Geser buffer yang sudah dikonsumsi
                    rx_buf.drain(0..consumed);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Idle — jika ingin TESTFR saat idle, aktifkan flag SEND_TESTFR_WHEN_IDLE
            }
            Err(e) => {
                eprintln!("Kesalahan saat membaca: {}", e);
                break;
            }
        }

        // (Opsional) kirim TESTFR act jika idle > 25 detik (default: off agar ACK-only murni)
        if SEND_TESTFR_WHEN_IDLE && last_read.elapsed() > Duration::from_secs(25) {
            let test_act = [0x68, 0x04, U_TESTFR_ACT, 0x00, 0x00, 0x00];
            // Lewat gatekeeper juga (akan diblok bila ACK_ONLY true)
            if let Err(e) = TxPolicy::enforce_static(&test_act) {
                println!("(Blok) TESTFR act: {}", e);
            } else {
                println!("> TX TESTFR act (idle): {}", hex(&test_act));
                let _ = stream.write_all(&test_act);
            }
            last_read = Instant::now();
        }
    }

    Ok(())
}

// ================= Gatekeeper TX (blokir frame terlarang) =================
struct TxPolicy {
    startdt_sent: bool,
}
impl TxPolicy {
    fn new() -> Self { Self { startdt_sent: false } }

    fn send_startdt(&mut self, stream: &mut TcpStream) -> std::io::Result<()> {
        if self.startdt_sent {
            println!("(Lewati) STARTDT act sudah pernah dikirim.");
            return Ok(());
        }
        let apdu = [0x68u8, 0x04, U_STARTDT_ACT, 0x00, 0x00, 0x00];
        self.enforce(&apdu).map_err(ioerr)?;
        println!("> TX STARTDT act: {}", hex(&apdu));
        stream.write_all(&apdu)?;
        self.startdt_sent = true;
        Ok(())
    }

    fn send_s_ack(&mut self, stream: &mut TcpStream, nr: u16, reason: &str) -> std::io::Result<()> {
        let apdu = build_s_ack(nr);
        self.enforce(&apdu).map_err(ioerr)?;
        println!("> TX S-ACK N(R)={} (reason: {}) {}", nr, reason, hex(&apdu));
        stream.write_all(&apdu)
    }

    fn enforce(&self, apdu: &[u8]) -> Result<(), String> {
        Self::enforce_static(apdu)
    }

    /// Versi statis (bisa dipakai di luar instance)
    fn enforce_static(apdu: &[u8]) -> Result<(), String> {
        if apdu.len() < 6 || apdu[0] != 0x68 {
            return Err("APDU invalid/pendek".into());
        }
        let c = &apdu[2..6];

        // U-frame?
        if (c[0] & 0b11) == 0b11 {
            // Hanya izinkan STARTDT act bila ACK_ONLY == true
            if ACK_ONLY && c[0] != U_STARTDT_ACT {
                return Err(format!("U-frame 0x{:02X} diblok (ACK-only).", c[0]));
            }
            return Ok(());
        }

        // S-frame? (ACK selalu diizinkan)
        if (c[0] & 0b01) == 0b01 && (c[0] & 0b10) == 0 {
            return Ok(());
        }

        // I-frame?
        if (c[0] & 0b01) == 0 {
            if ACK_ONLY {
                return Err("I-frame OUT diblok (ACK-only mode).".into());
            }
            // Jika nanti ACK_ONLY dimatikan, tetap lindungi dari 45/46
            if apdu.len() >= 7 {
                let type_id = apdu[6];
                if FORBIDDEN_TYPE_IDS.contains(&type_id) {
                    return Err(format!("ASDU type {} diblok (anti-45/46).", type_id));
                }
            } else {
                return Err("I-frame OUT tanpa ASDU lengkap diblok.".into());
            }
            return Ok(());
        }

        Err("Frame OUT tidak dikenal—diblok.".into())
    }
}

fn ioerr(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

// ================= Parser & util =================

/// Mengambil satu APDU utuh dari buffer bila tersedia.
/// Format: 0x68, LEN, lalu LEN byte berikutnya (APCI[4] + ASDU[Len-4])
fn take_one_apdu(buf: &[u8]) -> Option<(&[u8], usize)> {
    if buf.len() < 2 { return None; }
    // Resinkronisasi: cari start 0x68
    let mut start = 0usize;
    while start < buf.len() && buf[start] != 0x68 { start += 1; }
    if start >= buf.len() - 1 { return None; } // tidak cukup untuk baca LEN
    let len = buf[start + 1] as usize;
    let total = 2 + len;
    if buf.len() < start + total { return None; } // belum utuh
    let apdu = &buf[start..start + total];
    Some((apdu, start + total))
}

#[derive(Debug, PartialEq, Eq)]
enum UType {
    StartDtAct,
    StartDtCon,
    StopDtAct,
    StopDtCon,
    TestFrAct,
    TestFrCon,
    Other(u8),
}
impl std::fmt::Display for UType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UType::StartDtAct => write!(f, "STARTDT act"),
            UType::StartDtCon => write!(f, "STARTDT con"),
            UType::StopDtAct  => write!(f, "STOPDT act"),
            UType::StopDtCon  => write!(f, "STOPDT con"),
            UType::TestFrAct  => write!(f, "TESTFR act"),
            UType::TestFrCon  => write!(f, "TESTFR con"),
            UType::Other(b)   => write!(f, "U-other (0x{:02X})", b),
        }
    }
}

#[derive(Debug)]
struct AsduSummary {
    type_id: u8,
    vsq: u8,
    cot: u8,
    casdu: u16,
    ioa_first: u32, // jika VSQ.SQ=1 maka ini IOA pertama
}

#[derive(Debug)]
enum Frame {
    U(UType),
    S { nr: u16 },
    I { ns: u16, nr: u16, asdu: Option<AsduSummary> },
    Unknown,
}

fn classify_apdu(apdu: &[u8]) -> Frame {
    if apdu.len() < 6 || apdu[0] != 0x68 { return Frame::Unknown; }
    let len = apdu[1] as usize;
    if len < 4 { return Frame::Unknown; }
    let c = &apdu[2..6];

    // U-frame: bit0=1, bit1=1 pada byte kontrol 1
    if (c[0] & 0b11) == 0b11 {
        let ut = match c[0] {
            U_STARTDT_ACT => UType::StartDtAct,
            U_STARTDT_CON => UType::StartDtCon,
            U_STOPDT_ACT  => UType::StopDtAct,
            U_STOPDT_CON  => UType::StopDtCon,
            U_TESTFR_ACT  => UType::TestFrAct,
            U_TESTFR_CON  => UType::TestFrCon,
            other         => UType::Other(other),
        };
        return Frame::U(ut);
    }

    // S-frame: bit0=1, bit1=0
    if (c[0] & 0b01) == 0b01 && (c[0] & 0b10) == 0 {
        let nr = (((c[3] as u16) << 8) | (c[2] as u16)) >> 1;
        return Frame::S { nr };
    }

    // I-frame: bit0=0
    if (c[0] & 0b01) == 0 {
        let ns = (((c[1] as u16) << 8) | (c[0] as u16)) >> 1;
        let nr = (((c[3] as u16) << 8) | (c[2] as u16)) >> 1;

        // Coba ringkas ASDU (jika ada)
        let asdu_off = 6usize;
        if apdu.len() > asdu_off {
            let asdu = parse_asdu(&apdu[asdu_off..]);
            return Frame::I { ns, nr, asdu };
        } else {
            return Frame::I { ns, nr, asdu: None };
        }
    }

    Frame::Unknown
}

fn parse_asdu(asdu: &[u8]) -> Option<AsduSummary> {
    // Struktur minimum: 6 byte header ASDU + IOA (opsional)
    if asdu.len() < 6 { return None; }
    let type_id = asdu[0];
    let vsq = asdu[1];
    let cot = asdu[2] & 0x3F; // test/neg bit di atasnya
    let casdu = asdu.get(4).copied().unwrap_or(0) as u16
        | ((asdu.get(5).copied().unwrap_or(0) as u16) << 8);

    // IOA (3 byte) — hanya ambil IOA pertama bila tersedia
    let ioa_first = if asdu.len() >= 9 {
        (asdu[6] as u32) | ((asdu[7] as u32) << 8) | ((asdu[8] as u32) << 16)
    } else {
        0
    };

    Some(AsduSummary { type_id, vsq, cot, casdu, ioa_first })
}

fn build_s_ack(nr: u16) -> [u8; 6] {
    // 0x68, 0x04, 0x01, 0x00, (2*NR LSB), (2*NR MSB)
    let v = (nr << 1) as u16;
    [0x68, 0x04, 0x01, 0x00, (v & 0xFF) as u8, (v >> 8) as u8]
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

// ====== Util sequence (15-bit) ======
const SEQ_MOD: u16 = 1 << 15; // 32768

#[inline]
fn seq_inc(n: u16) -> u16 {
    (n + 1) & (SEQ_MOD - 1)
}

/// Jarak modular: banyaknya langkah dari b -> a (a - b mod 32768)
#[inline]
fn seq_distance(a: u16, b: u16) -> u16 {
    ((a as i32 - b as i32 + SEQ_MOD as i32) % SEQ_MOD as i32) as u16
}

fn asdu_type_name(type_id: u8) -> Option<&'static str> {
    match type_id {
        1  => Some("M_SP_NA_1"),
        3  => Some("M_DP_NA_1"),
        9  => Some("M_ME_NA_1"),
        11 => Some("M_ME_NB_1"),
        13 => Some("M_ME_NC_1"),
        15 => Some("M_IT_NA_1"),
        30 => Some("M_SP_TB_1"),
        31 => Some("M_DP_TB_1"),
        34 => Some("M_ME_TD_1"),
        35 => Some("M_ME_TE_1"),
        36 => Some("M_ME_TF_1"),
        37 => Some("M_IT_TB_1"),
        45 => Some("C_SC_NA_1"),
        46 => Some("C_DC_NA_1"),
        47 => Some("C_RC_NA_1"),
        100 => Some("C_IC_NA_1"),
        _ => None,
    }
}
