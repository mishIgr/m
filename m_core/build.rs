fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = "src/generated";
    std::fs::create_dir_all(out_dir)?;
    
    std::env::set_var("PROTOC", protobuf_src::protoc());
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/generated")
        .compile(
            &["./proto/messenger.proto"],
            &["./proto/"],
        )?;
    Ok(())
}
