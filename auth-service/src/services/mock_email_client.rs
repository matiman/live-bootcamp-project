use color_eyre::eyre::Result;
use secrecy::ExposeSecret;

use crate::domain::{Email, EmailClient};

pub struct MockEmailClient;

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    #[tracing::instrument(name = "Send email", skip_all)]
    async fn send_email(&self, recipient: &Email, subject: &str, content: &str) -> Result<()> {
        // Our mock email client will simply log the recipient, subject, and content to standard output
        tracing::info!(
            "Sending email to {} with subject: {} and content: {}",
            recipient.as_ref().expose_secret().to_string(),
            subject,
            content
        );

        Ok(())
    }
}
