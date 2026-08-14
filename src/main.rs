use std::{mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr},
    sync::{LazyLock, RwLock},
    fs::File,
    io::{BufReader,BufRead}, 
    str::{FromStr}, 
    collections::HashMap    } ;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::{MapFlags, MapCore};
use anyhow::{bail, Result};
use structopt::StructOpt;
use crate::trial::XdpFirewallSkelBuilder;
mod trial {
    include!("xdp_firewall.skel.rs");
}

#[derive(StructOpt)]
struct Command {
    /// verbose output
    #[structopt(long, short)]
    verbose: bool,
    /// glibc path
    #[structopt(long, short, default_value = "/lib/x86_64-linux-gnu/libc.so.6")]
    glibc: String,
    #[structopt(long, short)]
    /// pid to observe
    pid: Option<i32>,
    
}

static BLOCKED_IP_MAP: LazyLock<RwLock<HashMap<Ipv4Addr, u8>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

// 🦀🌊☕😴🦀🌊☕😴🦀🌊☕😴🦀🌊☕😴🦀🌊☕😴🦀🌊☕😴🦀🌊☕😴🦀🌊☕😴🦀🌊☕😴🦀🌊☕😴🦀🌊☕😴

fn convert_blocked_ip_to_map()-> Result<(), Box<dyn std::error::Error>>{

    // Open the file
    let file = File::open("blocked_ip.txt")?;
    let reader = BufReader::new(file);

    println!("Reading file line-by-line:\n ");

    {let mut blocked_ip = BLOCKED_IP_MAP.write().unwrap();
    // Read each line from the file
    for line_result in reader.lines(){
        let line = line_result?;
        let line = Ipv4Addr::from_str(line.trim())?;
        blocked_ip.insert(line, 1);

    }}

    // println!("{:?}", BLOCKED_IP_MAP);
        Ok(())
        
        
        }
// fn main(){
//     convert_blocked_ip_to_map();
// }
        
// /*

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };

    if ret != 0 {
        bail!("Failed to increase rlimit: {}", std::io::Error::last_os_error());
    }

    Ok(())
}
fn main() -> Result<()>{
    convert_blocked_ip_to_map();
    // println!("Proc Event Stuff:\n");
    println!("My PID: {}",std::process::id() );
    let opts = Command::from_args();

    let mut skel_builder = XdpFirewallSkelBuilder::default();

    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }
    
    bump_memlock_rlimit()?;
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    
    // Sending userspace - ./target/debug/edr-agent PID to kernspace 'agent_tgid'
    let mut skel = open_skel.load()?;

    for (ip, val) in BLOCKED_IP_MAP.read().unwrap().iter(){

        let key = u32::from(*ip);

        skel.maps.my_map.update(
            &key.to_ne_bytes(),
            &[*val],
            MapFlags::ANY,
        )?;
    }   
    
    Ok(())
}

 
//load the skeleton
//upload the blocked ip text file into the map */