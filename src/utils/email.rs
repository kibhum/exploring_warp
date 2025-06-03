use dotenv;
use sendgrid::v3::{Content, Email, Message, Personalization, Sender};
use std::env;

pub async fn send_mail() {
    dotenv::from_filename("config.env").ok();
    let api_key = env::var("SENDGRID_API_KEY").expect("SENDGRID_API_KEY must be set");

    let from_email = env::var("SENDGRID_FROM_MAIL").expect("SENDGRID_FROM_MAIL must be set");

    let to_email = env::var("SENDGRID_TO_MAIL").expect("SENDGRID_TO_MAIL must be set");

    let sender = Sender::new(api_key, None);

    let from = Email::new(from_email);
    let to = Email::new(to_email);

    let content = Content::new()
        .set_content_type("text/plain")
        .set_value("Hello from Rust using SendGrid!");

    let personalization = Personalization::new(to.clone());

    let message = Message::new(from)
        .set_subject("Test Email from Rust")
        .add_content(content)
        .add_personalization(personalization);

    match sender.send(&message).await {
        Ok(response) => {
            println!("Status: {}", response.status());

            match response.text().await {
                Ok(body) => println!("Response body: {}", body),
                Err(e) => eprintln!("Failed to read response body: {}", e),
            }
        }
        Err(error) => {
            eprintln!("Failed to send email: {:?}", error);
        }
    }
}
