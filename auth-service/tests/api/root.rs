use test_macros::with_cleanup;

#[with_cleanup]
async fn root_returns_auth_ui() {
    // app is already available from macro
    let response = app.get_root().await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}
