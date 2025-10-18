use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

pub struct HashmapUserStore {
    //make this thread safe and mutable that can be accessed by multiple threads one write and multiple read
    users: Arc<RwLock<HashMap<Email, User>>>,
}

impl Default for HashmapUserStore {
    fn default() -> Self {
        HashmapUserStore {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Return `UserStoreError::UserAlreadyExists` if the user already exists,
        // otherwise insert the user into the hashmap and return `Ok(())`.
        if self.users.read().await.contains_key(&user.email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.write().await.insert(user.email.clone(), user);
            Ok(())
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .read()
            .await
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        if &user.password == password {
            Ok(())
        } else {
            Err(UserStoreError::InvalidCredentials)
        }
    }
}

// TODO: Add unit tests for your `HashmapUserStore` implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com", "pasword123", false).unwrap();

        assert_eq!(store.add_user(user.clone()).await, Ok(()));
        assert_eq!(
            store.add_user(user.clone()).await,
            Err(UserStoreError::UserAlreadyExists)
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com", "pasword123", false).unwrap();
        store.add_user(user.clone()).await.unwrap();
        assert_eq!(store.get_user(&user.email).await, Ok(user));
        assert_eq!(
            store
                .get_user(&Email::parse("invalid_email@gmail.com").unwrap())
                .await,
            Err(UserStoreError::UserNotFound)
        );
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com", "pas454ord123", false).unwrap();
        store.add_user(user.clone()).await.unwrap();
        assert_eq!(
            store.validate_user(&user.email, &user.password).await,
            Ok(())
        );
        assert_eq!(
            store
                .validate_user(&user.email, &Password::parse("wrfddfonord").unwrap())
                .await,
            Err(UserStoreError::InvalidCredentials)
        );
    }
}
