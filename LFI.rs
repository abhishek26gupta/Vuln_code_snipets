// ============================================================
// VULNERABILITY: Path Traversal via insufficient sanitisation
// ---------------------------------------------------------------
// filename.replace("../", "") only removes ONE occurrence of
// "../". An attacker can bypass it with "....//etc/passwd"
// which becomes "../etc/passwd" after the single replacement.
//
// FIX: Use Path::canonicalize() and verify the result is
//      inside the allowed upload directory.
// ============================================================

// Cargo.toml dependencies needed:
//   actix-web = "4"
//   actix-files = "0.6"

// ============================================================
// curl "http://127.0.0.1:1337/uploads/....//....//....//etc/passwd"

// curl "http://127.0.0.1:1337/uploads/..%2F..%2Fetc%2Fpasswd"
// ============================================================

use actix_files as fs;
use actix_web::http::header::{ContentDisposition, DispositionType};
use actix_web::{web, get, App, Error, HttpServer};

#[get("/uploads/{filename:.*}")]
async fn serve(filename: web::Path<String>) -> Result<fs::NamedFile, Error> {
    // VULNERABLE: single replace does not stop "....//etc/passwd" → "../etc/passwd"
    let safe_path = filename.replace("../", "");
    let file      = fs::NamedFile::open(safe_path)?;
    Ok(file
        .use_last_modified(true)
        .set_content_disposition(ContentDisposition {
            disposition: DispositionType::Inline,
            parameters: vec![],
        }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(serve))
        .bind(("127.0.0.1", 1337))?
        .run()
        .await
}
