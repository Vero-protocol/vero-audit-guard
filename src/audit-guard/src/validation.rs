/// Security Validation Module
/// Provides validation utilities for improving system resilience against vulnerabilities
/// All validation functions follow Rust safety standards

use std::collections::HashSet;

/// Validation result type
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validation error with context
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
    pub code: String,
}

impl ValidationError {
    pub fn new(field: impl Into<String>, message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            code: code.into(),
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.code, self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Address validation utilities for Stellar addresses
pub mod address {
    use super::*;

    /// Validate a Stellar address (G... or M...)
    /// Returns the address if valid, error otherwise
    pub fn validate_stellar_address(address: &str) -> ValidationResult<String> {
        // Basic validation: starts with G or M, proper length
        if address.is_empty() {
            return Err(ValidationError::new(
                "address",
                "Address cannot be empty",
                "ADDRESS_EMPTY",
            ));
        }

        if address.len() != 56 {
            return Err(ValidationError::new(
                "address",
                format!("Address must be 56 characters, got {}", address.len()),
                "ADDRESS_INVALID_LENGTH",
            ));
        }

        let first_char = address.chars().next().unwrap();
        if first_char != 'G' && first_char != 'M' {
            return Err(ValidationError::new(
                "address",
                "Address must start with 'G' or 'M'",
                "ADDRESS_INVALID_PREFIX",
            ));
        }

        // Check alphanumeric (base32)
        if !address.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(ValidationError::new(
                "address",
                "Address must contain only alphanumeric characters",
                "ADDRESS_INVALID_CHARACTERS",
            ));
        }

        Ok(address.to_string())
    }

    /// Validate that an address is in an authorized list
    pub fn validate_authorized(
        address: &str,
        authorized: &HashSet<String>,
    ) -> ValidationResult<String> {
        let validated = validate_stellar_address(address)?;
        
        if !authorized.contains(&validated) {
            return Err(ValidationError::new(
                "address",
                format!("Address {} is not authorized", address),
                "ADDRESS_UNAUTHORIZED",
            ));
        }

        Ok(validated)
    }
}

/// Input validation utilities for preventing injection attacks
pub mod input {
    use super::*;

    /// Validate that a string doesn't contain SQL injection patterns
    pub fn validate_no_sql_injection(input: &str) -> ValidationResult<String> {
        let dangerous_patterns = [
            "--", "/*", "*/", "xp_", "sp_", "exec", "execute",
            "drop ", "delete ", "insert ", "update ", "select ",
        ];

        let lower = input.to_lowercase();
        for pattern in dangerous_patterns {
            if lower.contains(pattern) {
                return Err(ValidationError::new(
                    "input",
                    format!("Input contains potentially dangerous pattern: {}", pattern),
                    "SQL_INJECTION_DETECTED",
                ));
            }
        }

        Ok(input.to_string())
    }

    /// Validate that a string doesn't contain command injection patterns
    pub fn validate_no_command_injection(input: &str) -> ValidationResult<String> {
        let dangerous_chars = ['|', '&', ';', '`', '$', '(', ')', '<', '>', '\n', '\r'];

        for ch in dangerous_chars {
            if input.contains(ch) {
                return Err(ValidationError::new(
                    "input",
                    format!("Input contains potentially dangerous character: {}", ch),
                    "COMMAND_INJECTION_DETECTED",
                ));
            }
        }

        Ok(input.to_string())
    }

    /// Validate string length is within bounds
    pub fn validate_length(
        input: &str,
        min: usize,
        max: usize,
        field: &str,
    ) -> ValidationResult<String> {
        let len = input.len();
        
        if len < min {
            return Err(ValidationError::new(
                field,
                format!("{} must be at least {} characters, got {}", field, min, len),
                "LENGTH_TOO_SHORT",
            ));
        }

        if len > max {
            return Err(ValidationError::new(
                field,
                format!("{} must be at most {} characters, got {}", field, max, len),
                "LENGTH_TOO_LONG",
            ));
        }

        Ok(input.to_string())
    }

    /// Validate that a string is alphanumeric
    pub fn validate_alphanumeric(input: &str, field: &str) -> ValidationResult<String> {
        if !input.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return Err(ValidationError::new(
                field,
                format!("{} must contain only alphanumeric characters, underscores, and hyphens", field),
                "INVALID_CHARACTERS",
            ));
        }

        Ok(input.to_string())
    }
}

/// Numeric validation utilities for preventing overflow and range issues
pub mod numeric {
    use super::*;

    /// Validate that a number is within a safe range
    pub fn validate_range<T>(
        value: T,
        min: T,
        max: T,
        field: &str,
    ) -> ValidationResult<T>
    where
        T: PartialOrd + std::fmt::Display + Copy,
    {
        if value < min {
            return Err(ValidationError::new(
                field,
                format!("{} must be at least {}, got {}", field, min, value),
                "VALUE_TOO_LOW",
            ));
        }

        if value > max {
            return Err(ValidationError::new(
                field,
                format!("{} must be at most {}, got {}", field, max, value),
                "VALUE_TOO_HIGH",
            ));
        }

        Ok(value)
    }

    /// Validate that a number is positive (> 0)
    pub fn validate_positive<T>(value: T, field: &str) -> ValidationResult<T>
    where
        T: PartialOrd + std::fmt::Display + Copy + From<u8>,
    {
        if value <= T::from(0) {
            return Err(ValidationError::new(
                field,
                format!("{} must be positive, got {}", field, value),
                "VALUE_NOT_POSITIVE",
            ));
        }

        Ok(value)
    }

    /// Validate that a percentage is between 0 and 100
    pub fn validate_percentage(value: u32, field: &str) -> ValidationResult<u32> {
        validate_range(value, 0, 100, field)
    }
}

/// Data structure validation utilities
pub mod structure {
    use super::*;

    /// Validate that a collection is not empty
    pub fn validate_not_empty<T>(
        collection: &[T],
        field: &str,
    ) -> ValidationResult<()> {
        if collection.is_empty() {
            return Err(ValidationError::new(
                field,
                format!("{} cannot be empty", field),
                "COLLECTION_EMPTY",
            ));
        }

        Ok(())
    }

    /// Validate collection size is within bounds
    pub fn validate_collection_size<T>(
        collection: &[T],
        min: usize,
        max: usize,
        field: &str,
    ) -> ValidationResult<()> {
        let len = collection.len();

        if len < min {
            return Err(ValidationError::new(
                field,
                format!("{} must contain at least {} items, got {}", field, min, len),
                "COLLECTION_TOO_SMALL",
            ));
        }

        if len > max {
            return Err(ValidationError::new(
                field,
                format!("{} must contain at most {} items, got {}", field, max, len),
                "COLLECTION_TOO_LARGE",
            ));
        }

        Ok(())
    }

    /// Validate that all items in a collection are unique
    pub fn validate_unique<T>(
        collection: &[T],
        field: &str,
    ) -> ValidationResult<()>
    where
        T: std::hash::Hash + Eq,
    {
        let mut seen = HashSet::new();
        for item in collection {
            if !seen.insert(item) {
                return Err(ValidationError::new(
                    field,
                    format!("{} must contain unique items", field),
                    "DUPLICATE_ITEMS",
                ));
            }
        }

        Ok(())
    }
}

/// Compose multiple validation functions
pub fn validate_all<T>(
    validators: Vec<Box<dyn Fn(&T) -> ValidationResult<()>>>,
    value: &T,
) -> Result<(), Vec<ValidationError>> {
    let errors: Vec<ValidationError> = validators
        .iter()
        .filter_map(|validator| validator(value).err())
        .collect();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_stellar_address_valid() {
        let valid = "GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ234567890ABCDE";
        assert!(address::validate_stellar_address(valid).is_ok());
    }

    #[test]
    fn test_validate_stellar_address_invalid_length() {
        let short = "GABC123";
        assert!(address::validate_stellar_address(short).is_err());
    }

    #[test]
    fn test_validate_stellar_address_invalid_prefix() {
        let invalid = "XABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ234567890ABCDE";
        let result = address::validate_stellar_address(invalid);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "ADDRESS_INVALID_PREFIX");
    }

    #[test]
    fn test_validate_authorized_address() {
        let mut authorized = HashSet::new();
        authorized.insert("GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ234567890ABCDE".to_string());

        let valid = "GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ234567890ABCDE";
        assert!(address::validate_authorized(valid, &authorized).is_ok());

        let unauthorized = "GXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ234567890ABCDE";
        let result = address::validate_authorized(unauthorized, &authorized);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "ADDRESS_UNAUTHORIZED");
    }

    #[test]
    fn test_validate_no_sql_injection() {
        assert!(input::validate_no_sql_injection("normal input").is_ok());
        assert!(input::validate_no_sql_injection("'; DROP TABLE users--").is_err());
        assert!(input::validate_no_sql_injection("SELECT * FROM").is_err());
    }

    #[test]
    fn test_validate_no_command_injection() {
        assert!(input::validate_no_command_injection("normal input").is_ok());
        assert!(input::validate_no_command_injection("test | cat /etc/passwd").is_err());
        assert!(input::validate_no_command_injection("test && rm -rf /").is_err());
        assert!(input::validate_no_command_injection("$(whoami)").is_err());
    }

    #[test]
    fn test_validate_length() {
        let result = input::validate_length("test", 3, 10, "field");
        assert!(result.is_ok());

        let too_short = input::validate_length("ab", 3, 10, "field");
        assert!(too_short.is_err());
        assert_eq!(too_short.unwrap_err().code, "LENGTH_TOO_SHORT");

        let too_long = input::validate_length("this is way too long", 3, 10, "field");
        assert!(too_long.is_err());
        assert_eq!(too_long.unwrap_err().code, "LENGTH_TOO_LONG");
    }

    #[test]
    fn test_validate_alphanumeric() {
        assert!(input::validate_alphanumeric("test123", "field").is_ok());
        assert!(input::validate_alphanumeric("test-name_123", "field").is_ok());
        assert!(input::validate_alphanumeric("test@name", "field").is_err());
        assert!(input::validate_alphanumeric("test name", "field").is_err());
    }

    #[test]
    fn test_validate_range() {
        assert!(numeric::validate_range(5, 0, 10, "field").is_ok());
        assert!(numeric::validate_range(-1, 0, 10, "field").is_err());
        assert!(numeric::validate_range(11, 0, 10, "field").is_err());
    }

    #[test]
    fn test_validate_positive() {
        assert!(numeric::validate_positive(5, "field").is_ok());
        assert!(numeric::validate_positive(0, "field").is_err());
        assert!(numeric::validate_positive(-5, "field").is_err());
    }

    #[test]
    fn test_validate_percentage() {
        assert!(numeric::validate_percentage(50, "field").is_ok());
        assert!(numeric::validate_percentage(0, "field").is_ok());
        assert!(numeric::validate_percentage(100, "field").is_ok());
        assert!(numeric::validate_percentage(101, "field").is_err());
    }

    #[test]
    fn test_validate_not_empty() {
        let non_empty = vec![1, 2, 3];
        assert!(structure::validate_not_empty(&non_empty, "field").is_ok());

        let empty: Vec<i32> = vec![];
        assert!(structure::validate_not_empty(&empty, "field").is_err());
    }

    #[test]
    fn test_validate_collection_size() {
        let collection = vec![1, 2, 3];
        assert!(structure::validate_collection_size(&collection, 1, 5, "field").is_ok());
        assert!(structure::validate_collection_size(&collection, 5, 10, "field").is_err());
        assert!(structure::validate_collection_size(&collection, 1, 2, "field").is_err());
    }

    #[test]
    fn test_validate_unique() {
        let unique = vec![1, 2, 3, 4, 5];
        assert!(structure::validate_unique(&unique, "field").is_ok());

        let duplicates = vec![1, 2, 3, 2, 5];
        let result = structure::validate_unique(&duplicates, "field");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "DUPLICATE_ITEMS");
    }
}
