pub mod ca_authority {
    tonic::include_proto!("ca_authority");
}

pub mod workload {
    // When there's no package name, Prost names the module "_"
    tonic::include_proto!("_");
}

pub mod proxy {
    tonic::include_proto!("proxy");
    pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("proxy_descriptor");
}
