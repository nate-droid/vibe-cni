use std::collections::HashMap;
use std::env;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

// CNI specification structures
#[derive(Debug, Serialize, Deserialize)]
struct CNIConfig {
    #[serde(rename = "cniVersion")]
    cni_version: String,
    name: String,
    #[serde(rename = "type")]
    plugin_type: String,
    bridge: Option<String>,
    #[serde(rename = "isGateway")]
    is_gateway: Option<bool>,
    #[serde(rename = "isDefaultGateway")]
    is_default_gateway: Option<bool>,
    #[serde(rename = "forceAddress")]
    force_address: Option<bool>,
    #[serde(rename = "ipMasq")]
    ip_masq: Option<bool>,
    mtu: Option<u32>,
    #[serde(rename = "hairpinMode")]
    hairpin_mode: Option<bool>,
    ipam: Option<IPAMConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IPAMConfig {
    #[serde(rename = "type")]
    plugin_type: String,
    subnet: Option<String>,
    #[serde(rename = "rangeStart")]
    range_start: Option<String>,
    #[serde(rename = "rangeEnd")]
    range_end: Option<String>,
    gateway: Option<String>,
    routes: Option<Vec<Route>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Route {
    dst: String,
    gw: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CNIArgs {
    #[serde(rename = "containerID")]
    container_id: String,
    netns: String,
    #[serde(rename = "ifName")]
    if_name: String,
    args: Option<String>,
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CNIResult {
    #[serde(rename = "cniVersion")]
    cni_version: String,
    interfaces: Vec<Interface>,
    ips: Vec<IPConfig>,
    routes: Option<Vec<Route>>,
    dns: Option<DNSConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Interface {
    name: String,
    mac: Option<String>,
    sandbox: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IPConfig {
    address: String,
    gateway: Option<String>,
    interface: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DNSConfig {
    nameservers: Vec<String>,
    domain: Option<String>,
    search: Option<Vec<String>>,
    options: Option<Vec<String>>,
}

#[derive(Debug)]
struct CNIError {
    code: u32,
    msg: String,
    details: Option<String>,
}

impl CNIError {
    fn new(code: u32, msg: &str) -> Self {
        CNIError {
            code,
            msg: msg.to_string(),
            details: None,
        }
    }
}

struct EbpfCNI {
    config: CNIConfig,
    args: CNIArgs,
}

impl EbpfCNI {
    fn new() -> Result<Self, CNIError> {
        // Read CNI config from stdin
        let mut stdin = io::stdin();
        let mut config_data = String::new();
        stdin.read_to_string(&mut config_data)
            .map_err(|_| CNIError::new(2, "Failed to read config from stdin"))?;

        let config: CNIConfig = serde_json::from_str(&config_data)
            .map_err(|_| CNIError::new(2, "Failed to parse CNI config"))?;

        // Parse CNI environment variables
        let container_id = env::var("CNI_CONTAINERID")
            .map_err(|_| CNIError::new(2, "CNI_CONTAINERID not set"))?;
        let netns = env::var("CNI_NETNS")
            .map_err(|_| CNIError::new(2, "CNI_NETNS not set"))?;
        let if_name = env::var("CNI_IFNAME")
            .map_err(|_| CNIError::new(2, "CNI_IFNAME not set"))?;
        let args = env::var("CNI_ARGS").ok();
        let path = env::var("CNI_PATH")
            .map_err(|_| CNIError::new(2, "CNI_PATH not set"))?;

        let cni_args = CNIArgs {
            container_id,
            netns,
            if_name,
            args,
            path,
        };

        Ok(EbpfCNI {
            config,
            args: cni_args,
        })
    }

    fn cmd_add(&self) -> Result<CNIResult, CNIError> {
        // This is where we'll eventually integrate eBPF programs
        // For now, let's create a basic bridge setup

        let bridge_name = self.config.bridge.as_deref()
            .unwrap_or("cni-ebpf0");

        // Create bridge if it doesn't exist
        self.ensure_bridge(bridge_name)?;

        // Create veth pair
        let host_veth = format!("veth{}", &self.args.container_id[..8]);
        let container_veth = &self.args.if_name;

        self.create_veth_pair(&host_veth, container_veth)?;

        // Move container end to netns
        self.move_to_netns(container_veth, &self.args.netns)?;

        // Attach host end to bridge
        self.attach_to_bridge(&host_veth, bridge_name)?;

        // Configure IP (basic IPAM for now)
        let ip = self.allocate_ip()?;
        self.configure_container_ip(&ip, container_veth)?;

        // TODO: Load eBPF programs here
        // self.load_ebpf_programs()?;

        Ok(CNIResult {
            cni_version: self.config.cni_version.clone(),
            interfaces: vec![
                Interface {
                    name: bridge_name.parse().unwrap(),
                    mac: None,
                    sandbox: None,
                },
                Interface {
                    name: container_veth.clone(),
                    mac: None,
                    sandbox: Some(self.args.netns.clone()),
                },
            ],
            ips: vec![IPConfig {
                address: format!("{}/24", ip),
                gateway: Some("10.244.0.1".to_string()),
                interface: Some(1), // container interface
            }],
            routes: Some(vec![Route {
                dst: "0.0.0.0/0".to_string(),
                gw: Some("10.244.0.1".to_string()),
            }]),
            dns: Some(DNSConfig {
                nameservers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
                domain: None,
                search: None,
                options: None,
            }),
        })
    }

    fn cmd_del(&self) -> Result<(), CNIError> {
        // Clean up veth pair and eBPF programs
        let host_veth = format!("veth{}", &self.args.container_id[..8]);

        // Delete host veth (container end should be cleaned up with netns)
        let _ = Command::new("ip")
            .args(&["link", "del", &host_veth])
            .output();

        // TODO: Unload eBPF programs here
        // self.unload_ebpf_programs()?;

        Ok(())
    }

    fn cmd_check(&self) -> Result<(), CNIError> {
        // Verify the setup is still valid
        // TODO: Check eBPF programs are still loaded and functioning
        Ok(())
    }

    fn ensure_bridge(&self, bridge_name: &str) -> Result<(), CNIError> {
        // Check if bridge exists
        let output = Command::new("ip")
            .args(&["link", "show", bridge_name])
            .output()
            .map_err(|_| CNIError::new(3, "Failed to check bridge"))?;

        if !output.status.success() {
            // Create bridge
            Command::new("ip")
                .args(&["link", "add", bridge_name, "type", "bridge"])
                .status()
                .map_err(|_| CNIError::new(3, "Failed to create bridge"))?;

            Command::new("ip")
                .args(&["link", "set", bridge_name, "up"])
                .status()
                .map_err(|_| CNIError::new(3, "Failed to bring bridge up"))?;

            // Set bridge IP
            Command::new("ip")
                .args(&["addr", "add", "10.244.0.1/24", "dev", bridge_name])
                .status()
                .map_err(|_| CNIError::new(3, "Failed to set bridge IP"))?;
        }

        Ok(())
    }

    fn create_veth_pair(&self, host_veth: &str, container_veth: &str) -> Result<(), CNIError> {
        Command::new("ip")
            .args(&["link", "add", host_veth, "type", "veth", "peer", "name", container_veth])
            .status()
            .map_err(|_| CNIError::new(3, "Failed to create veth pair"))?;

        Command::new("ip")
            .args(&["link", "set", host_veth, "up"])
            .status()
            .map_err(|_| CNIError::new(3, "Failed to bring host veth up"))?;

        Ok(())
    }

    fn move_to_netns(&self, interface: &str, netns: &str) -> Result<(), CNIError> {
        Command::new("ip")
            .args(&["link", "set", interface, "netns", netns])
            .status()
            .map_err(|_| CNIError::new(3, "Failed to move interface to netns"))?;

        Ok(())
    }

    fn attach_to_bridge(&self, interface: &str, bridge: &str) -> Result<(), CNIError> {
        Command::new("ip")
            .args(&["link", "set", interface, "master", bridge])
            .status()
            .map_err(|_| CNIError::new(3, "Failed to attach interface to bridge"))?;

        Ok(())
    }

    fn allocate_ip(&self) -> Result<Ipv4Addr, CNIError> {
        // Super basic IP allocation - in real implementation, this would be much more sophisticated
        // and probably stored in etcd or similar
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.args.container_id.hash(&mut hasher);
        let hash = hasher.finish();

        // Generate IP in 10.244.0.0/24 range
        let host_part = (hash % 254) as u8 + 2; // avoid .0 and .1
        Ok(Ipv4Addr::new(10, 244, 0, host_part))
    }

    fn configure_container_ip(&self, ip: &Ipv4Addr, interface: &str) -> Result<(), CNIError> {
        let netns = &self.args.netns;

        // Configure IP inside the container netns
        Command::new("ip")
            .args(&["netns", "exec", netns, "ip", "addr", "add",
                &format!("{}/24", ip), "dev", interface])
            .status()
            .map_err(|_| CNIError::new(3, "Failed to set container IP"))?;

        Command::new("ip")
            .args(&["netns", "exec", netns, "ip", "link", "set", interface, "up"])
            .status()
            .map_err(|_| CNIError::new(3, "Failed to bring container interface up"))?;

        // Set default route
        Command::new("ip")
            .args(&["netns", "exec", netns, "ip", "route", "add", "default", "via", "10.244.0.1"])
            .status()
            .map_err(|_| CNIError::new(3, "Failed to set default route"))?;

        Ok(())
    }

    // TODO: eBPF integration methods
    // fn load_ebpf_programs(&self) -> Result<(), CNIError> {
    //     // Load eBPF programs for traffic shaping, security policies, etc.
    //     Ok(())
    // }

    // fn unload_ebpf_programs(&self) -> Result<(), CNIError> {
    //     // Clean up eBPF programs
    //     Ok(())
    // }
}

fn main() {
    let command = env::var("CNI_COMMAND").unwrap_or_else(|_| "".to_string());

    let cni = match EbpfCNI::new() {
        Ok(cni) => cni,
        Err(e) => {
            eprintln!("{{\"code\":{},\"msg\":\"{}\"}}", e.code, e.msg);
            std::process::exit(1);
        }
    };

    let result = match command.as_str() {
        "ADD" => {
            match cni.cmd_add() {
                Ok(result) => {
                    println!("{}", serde_json::to_string(&result).unwrap());
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("{{\"code\":{},\"msg\":\"{}\"}}", e.code, e.msg);
                    std::process::exit(1);
                }
            }
        }
        "DEL" => {
            match cni.cmd_del() {
                Ok(_) => std::process::exit(0),
                Err(e) => {
                    eprintln!("{{\"code\":{},\"msg\":\"{}\"}}", e.code, e.msg);
                    std::process::exit(1);
                }
            }
        }
        "CHECK" => {
            match cni.cmd_check() {
                Ok(_) => std::process::exit(0),
                Err(e) => {
                    eprintln!("{{\"code\":{},\"msg\":\"{}\"}}", e.code, e.msg);
                    std::process::exit(1);
                }
            }
        }
        "VERSION" => {
            let version = r#"{"cniVersion":"1.0.0","supportedVersions":["0.3.0","0.3.1","0.4.0","1.0.0"]}"#;
            println!("{}", version);
            std::process::exit(0);
        }
        _ => {
            eprintln!("{{\"code\":7,\"msg\":\"unknown CNI command: {}\"}}", command);
            std::process::exit(1);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use tempfile::NamedTempFile;

    // Helper function to create a test CNI config
    fn create_test_config() -> CNIConfig {
        CNIConfig {
            cni_version: "1.0.0".to_string(),
            name: "ebpf-cni-test".to_string(),
            plugin_type: "ebpf-cni".to_string(),
            bridge: Some("test-br0".to_string()),
            is_gateway: Some(true),
            is_default_gateway: Some(true),
            force_address: None,
            ip_masq: Some(true),
            mtu: Some(1500),
            hairpin_mode: Some(true),
            ipam: Some(IPAMConfig {
                plugin_type: "host-local".to_string(),
                subnet: Some("10.244.0.0/24".to_string()),
                range_start: Some("10.244.0.10".to_string()),
                range_end: Some("10.244.0.250".to_string()),
                gateway: Some("10.244.0.1".to_string()),
                routes: Some(vec![Route {
                    dst: "0.0.0.0/0".to_string(),
                    gw: Some("10.244.0.1".to_string()),
                }]),
            }),
        }
    }

    // Helper function to set up test environment variables
    fn setup_test_env() -> (String, String, String) {
        let container_id = "test-container-123456789abcdef".to_string();
        let netns = "/var/run/netns/test-ns".to_string();
        let if_name = "eth0".to_string();

        unsafe { env::set_var("CNI_CONTAINERID", &container_id)};
        unsafe { env::set_var("CNI_NETNS", &netns)};
        unsafe { env::set_var("CNI_IFNAME", &if_name)};
        unsafe { env::set_var("CNI_PATH", "/opt/cni/bin")};
        unsafe { env::set_var("CNI_COMMAND", "ADD")};

        (container_id, netns, if_name)
    }

    // Helper to clean up test environment
    fn cleanup_test_env() {
        unsafe { env::remove_var("CNI_CONTAINERID")};
        unsafe {env::remove_var("CNI_NETNS")};
        unsafe { env::remove_var("CNI_IFNAME")};
        unsafe { env::remove_var("CNI_PATH")};
        unsafe { env::remove_var("CNI_COMMAND")};
    }

    #[test]
    fn test_cni_config_serialization() {
        let config = create_test_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: CNIConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.cni_version, deserialized.cni_version);
        assert_eq!(config.name, deserialized.name);
        assert_eq!(config.plugin_type, deserialized.plugin_type);
        assert_eq!(config.bridge, deserialized.bridge);
    }

    #[test]
    fn test_cni_result_serialization() {
        let result = CNIResult {
            cni_version: "1.0.0".to_string(),
            interfaces: vec![
                Interface {
                    name: "test-br0".to_string(),
                    mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
                    sandbox: None,
                },
                Interface {
                    name: "eth0".to_string(),
                    mac: Some("ff:ee:dd:cc:bb:aa".to_string()),
                    sandbox: Some("/var/run/netns/test".to_string()),
                },
            ],
            ips: vec![IPConfig {
                address: "10.244.0.100/24".to_string(),
                gateway: Some("10.244.0.1".to_string()),
                interface: Some(1),
            }],
            routes: Some(vec![Route {
                dst: "0.0.0.0/0".to_string(),
                gw: Some("10.244.0.1".to_string()),
            }]),
            dns: Some(DNSConfig {
                nameservers: vec!["8.8.8.8".to_string()],
                domain: Some("cluster.local".to_string()),
                search: Some(vec!["default.svc.cluster.local".to_string()]),
                options: None,
            }),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: CNIResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result.cni_version, deserialized.cni_version);
        assert_eq!(result.interfaces.len(), deserialized.interfaces.len());
        assert_eq!(result.ips.len(), deserialized.ips.len());
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    struct CNIArgs {
        container_id: String,
        netns: String,
        if_name: String,
        args: None,
        path: "/test".to_string(),
    }
    
    #[test]
    fn test_ip_allocation_consistency() {
        let container_id = "test-container-123";


        let mut cni_args = CNIArgs {
            container_id: container_id.to_string(),
            netns: "/test".to_string(),
            if_name: "eth0".to_string(),
            path: "/test".to_string(),
        };

        let cni = EbpfCNI {
            config: create_test_config(),
            args: cni_args.clone(),
        };

        // Same container ID should get same IP
        let ip1 = cni.allocate_ip().unwrap();
        let ip2 = cni.allocate_ip().unwrap();
        assert_eq!(ip1, ip2);

        // Different container ID should get different IP
        cni_args.container_id = "different-container-456".to_string();
        let cni2 = EbpfCNI {
            config: create_test_config(),
            args: cni_args,
        };
        let ip3 = cni2.allocate_ip().unwrap();
        assert_ne!(ip1, ip3);
    }

    #[test]
    fn test_ip_allocation_range() {
        let cni = EbpfCNI {
            config: create_test_config(),
            args: CNIArgs {
                container_id: "test".to_string(),
                netns: "/test".to_string(),
                if_name: "eth0".to_string(),
                args: None,
                path: "/test".to_string(),
            },
        };

        let ip = cni.allocate_ip().unwrap();

        // Should be in 10.244.0.0/24 range
        assert_eq!(ip.octets()[0], 10);
        assert_eq!(ip.octets()[1], 244);
        assert_eq!(ip.octets()[2], 0);

        // Should not be .0 or .1 (reserved)
        assert!(ip.octets()[3] >= 2);
        assert!(ip.octets()[3] <= 255);
    }

    #[test]
    fn test_cni_error_creation() {
        let error = CNIError::new(2, "Test error message");
        assert_eq!(error.code, 2);
        assert_eq!(error.msg, "Test error message");
        assert!(error.details.is_none());
    }

    #[test]
    fn test_missing_env_vars() {
        cleanup_test_env();

        // Should fail without required env vars
        let result = EbpfCNI::new();
        assert!(result.is_err());
    }

    #[test]
    fn test_env_var_parsing() {
        setup_test_env();

        // Create a temporary config file
        let config = create_test_config();
        let config_json = serde_json::to_string(&config).unwrap();

        // We can't easily test stdin reading in unit tests, but we can test
        // the parsing logic separately
        let parsed: CNIConfig = serde_json::from_str(&config_json).unwrap();
        assert_eq!(parsed.name, "ebpf-cni-test");

        cleanup_test_env();
    }

    #[test]
    fn test_veth_naming() {
        let container_id = "test-container-123456789abcdef";
        let expected_host_veth = "vethtest-con"; // first 8 chars after prefix

        let host_veth = format!("veth{}", &container_id[..8]);
        assert_eq!(host_veth, expected_host_veth);
    }

    #[test]
    fn test_route_structure() {
        let route = Route {
            dst: "192.168.1.0/24".to_string(),
            gw: Some("192.168.1.1".to_string()),
        };

        let json = serde_json::to_string(&route).unwrap();
        let parsed: Route = serde_json::from_str(&json).unwrap();

        assert_eq!(route.dst, parsed.dst);
        assert_eq!(route.gw, parsed.gw);
    }

    #[test]
    fn test_interface_structure() {
        let interface = Interface {
            name: "eth0".to_string(),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            sandbox: Some("/var/run/netns/test".to_string()),
        };

        let json = serde_json::to_string(&interface).unwrap();
        let parsed: Interface = serde_json::from_str(&json).unwrap();

        assert_eq!(interface.name, parsed.name);
        assert_eq!(interface.mac, parsed.mac);
        assert_eq!(interface.sandbox, parsed.sandbox);
    }

    #[test]
    fn test_dns_config() {
        let dns = DNSConfig {
            nameservers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            domain: Some("example.com".to_string()),
            search: Some(vec!["example.com".to_string(), "test.com".to_string()]),
            options: Some(vec!["ndots:2".to_string()]),
        };

        let json = serde_json::to_string(&dns).unwrap();
        let parsed: DNSConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(dns.nameservers, parsed.nameservers);
        assert_eq!(dns.domain, parsed.domain);
        assert_eq!(dns.search, parsed.search);
        assert_eq!(dns.options, parsed.options);
    }

    // Integration-style tests (these would need root privileges and actual network setup)
    #[cfg(feature = "integration_tests")]
    mod integration_tests {
        use super::*;

        #[test]
        #[ignore] // Run with --ignored flag and root privileges
        fn test_bridge_creation() {
            let cni = EbpfCNI {
                config: create_test_config(),
                args: CNIArgs {
                    container_id: "test".to_string(),
                    netns: "/test".to_string(),
                    if_name: "eth0".to_string(),
                    args: None,
                    path: "/test".to_string(),
                },
            };

            let bridge_name = "test-integration-br0";

            // Clean up any existing bridge
            let _ = Command::new("ip")
                .args(&["link", "del", bridge_name])
                .output();

            // Test bridge creation
            let result = cni.ensure_bridge(bridge_name);
            assert!(result.is_ok());

            // Verify bridge exists
            let output = Command::new("ip")
                .args(&["link", "show", bridge_name])
                .output()
                .unwrap();
            assert!(output.status.success());

            // Clean up
            let _ = Command::new("ip")
                .args(&["link", "del", bridge_name])
                .output();
        }

        #[test]
        #[ignore] // Run with --ignored flag and root privileges
        fn test_veth_creation() {
            let cni = EbpfCNI {
                config: create_test_config(),
                args: CNIArgs {
                    container_id: "test".to_string(),
                    netns: "/test".to_string(),
                    if_name: "eth0".to_string(),
                    args: None,
                    path: "/test".to_string(),
                },
            };

            let host_veth = "test-host-veth";
            let container_veth = "test-container-veth";

            // Clean up any existing interfaces
            let _ = Command::new("ip")
                .args(&["link", "del", host_veth])
                .output();

            // Test veth creation
            let result = cni.create_veth_pair(host_veth, container_veth);
            assert!(result.is_ok());

            // Verify veth pair exists
            let output = Command::new("ip")
                .args(&["link", "show", host_veth])
                .output()
                .unwrap();
            assert!(output.status.success());

            // Clean up
            let _ = Command::new("ip")
                .args(&["link", "del", host_veth])
                .output();
        }
    }

    // Benchmark tests for performance-critical operations
    #[cfg(feature = "bench")]
    mod bench_tests {
        use super::*;
        use std::time::Instant;

        #[test]
        fn bench_ip_allocation() {
            let cni = EbpfCNI {
                config: create_test_config(),
                args: CNIArgs {
                    container_id: "bench-test".to_string(),
                    netns: "/test".to_string(),
                    if_name: "eth0".to_string(),
                    args: None,
                    path: "/test".to_string(),
                },
            };

            let start = Instant::now();
            for _ in 0..1000 {
                let _ = cni.allocate_ip();
            }
            let duration = start.elapsed();

            println!("1000 IP allocations took: {:?}", duration);
            assert!(duration.as_millis() < 100); // Should be very fast
        }

        #[test]
        fn bench_json_parsing() {
            let config = create_test_config();
            let json = serde_json::to_string(&config).unwrap();

            let start = Instant::now();
            for _ in 0..1000 {
                let _: CNIConfig = serde_json::from_str(&json).unwrap();
            }
            let duration = start.elapsed();

            println!("1000 JSON parses took: {:?}", duration);
            assert!(duration.as_millis() < 50); // Should be very fast
        }
    }
}

// Test utilities for external testing
#[cfg(test)]
pub mod test_utils {
    use super::*;

    pub fn create_mock_cni() -> EbpfCNI {
        EbpfCNI {
            config: CNIConfig {
                cni_version: "1.0.0".to_string(),
                name: "mock-cni".to_string(),
                plugin_type: "ebpf-cni".to_string(),
                bridge: Some("mock-br0".to_string()),
                is_gateway: Some(true),
                is_default_gateway: Some(true),
                force_address: None,
                ip_masq: Some(true),
                mtu: Some(1500),
                hairpin_mode: Some(true),
                ipam: None,
            },
            args: CNIArgs {
                container_id: "mock-container".to_string(),
                netns: "/mock/netns".to_string(),
                if_name: "eth0".to_string(),
                args: None,
                path: "/mock/path".to_string(),
            },
        }
    }

    pub fn assert_valid_ipv4(ip_str: &str) {
        let _: std::net::Ipv4Addr = ip_str.parse().expect("Invalid IPv4 address");
    }

    pub fn assert_valid_cidr(cidr: &str) {
        let parts: Vec<&str> = cidr.split('/').collect();
        assert_eq!(parts.len(), 2);
        assert_valid_ipv4(parts[0]);
        let prefix: u8 = parts[1].parse().expect("Invalid CIDR prefix");
        assert!(prefix <= 32);
    }
}