use rand::prelude::*;

#[derive(Debug)]
pub struct User {
    pub name: String,
    pub password: String,
}

impl User {
    pub fn new(name: String) -> Self {
        assert!(!name.contains(' '));
        let mut rng = rand::thread_rng();
        let password: String = (0..16)
            .map(|_| {
                let choices = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                choices.chars().choose(&mut rng).unwrap()
            })
            .collect();
        Self { name, password }
    }

    pub fn check_password(&self, password: &str) -> bool {
        // TODO: Make constant-time
        self.password == password
    }
}
