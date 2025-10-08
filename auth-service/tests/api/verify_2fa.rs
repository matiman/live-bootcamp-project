use crate::helpers::TestApp;

#[tokio::test]
async fn verify_2fa_returns_ok_response() {
    let app = TestApp::new().await;

    let response = app.post_verify_2fa().await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
}