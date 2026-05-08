use std::env;

trait Validate {
    fn validate(&self, key: &str) -> Result<(), String>;
}

// Generic struct — monomorphization produces distinct _R symbols per T
struct DataProcessor<T> {
    data: Vec<T>,
}

impl<T: Copy + std::ops::Mul<Output = T> + std::ops::Add<Output = T> + From<u16>>
    DataProcessor<T>
{
    fn new(data: Vec<T>) -> Self {
        DataProcessor { data }
    }

    fn transform(&mut self, multiplier: T, offset: T) {
        for x in self.data.iter_mut() {
            *x = *x * multiplier + offset;
        }
    }

    fn data(&self) -> &[T] {
        &self.data
    }
}

struct License<'a> {
    key: &'a str,
}

impl<'a> License<'a> {
    fn new(key: &'a str) -> Self {
        License { key }
    }

    fn is_valid(&self) -> bool {
        if self.key.len() != 12 {
            return false;
        }
        let sum: i32 = self.key.bytes().map(|b| b as i32).sum();
        sum == 0x4B2
    }
}

struct LicenseValidator {
    _name: String,
    required_prefix: char,
}

impl LicenseValidator {
    fn new(name: &str, required_prefix: char) -> Self {
        LicenseValidator {
            _name: name.to_string(),
            required_prefix,
        }
    }
}

impl Validate for LicenseValidator {
    fn validate(&self, key: &str) -> Result<(), String> {
        if !key.starts_with(self.required_prefix) {
            return Err(format!("key must start with '{}'", self.required_prefix));
        }
        let lic = License::new(key);
        if lic.is_valid() {
            Ok(())
        } else {
            Err("checksum mismatch".to_string())
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <license_key>", args[0]);
        std::process::exit(1);
    }

    let validator = LicenseValidator::new("ProdValidator", 'A');

    match validator.validate(&args[1]) {
        Ok(()) => println!("Valid license!"),
        Err(e) => {
            eprintln!("Invalid license: {e}");
            std::process::exit(1);
        }
    }

    let mut proc = DataProcessor::new(vec![1i32, 2, 3, 4, 5]);
    proc.transform(2, 0xDEAD);
    let d = proc.data();
    println!("Processed: {} {} {}", d[0], d[1], d[2]);
}
