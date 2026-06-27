# Cryptographic Security Policy
# Validates that no insecure cryptographic algorithms are used in modified files

package pr.crypto

import data.lib.severity

# Banned algorithms and their detection patterns
banned_algorithms := [
    {
        "name": "MD5",
        "pattern": "(?i)md5['\"(]|md5$",
        "message": "MD5 is cryptographically broken and should not be used for security purposes."
    },
    {
        "name": "SHA1",
        "pattern": "(?i)sha1['\"(]|sha1$",
        "message": "SHA-1 is no longer considered secure against well-funded opponents."
    },
    {
        "name": "RC4",
        "pattern": "(?i)rc4['\"(]|rc4$",
        "message": "RC4 is insecure and has many known vulnerabilities."
    },
    {
        "name": "DES",
        "pattern": "(?i)des['\"(]|des$",
        "message": "DES has a small key size and can be brute-forced easily."
    }
]

# Rule: Detect usage of banned cryptographic algorithms
deny[msg] {
    some filename
    content := input.file_contents[filename]

    some i
    algo := banned_algorithms[i]
    re_match(algo.pattern, content)

    msg := {
        "rule": "INSECURE_CRYPTO_ALGORITHM",
        "severity": severity.CRITICAL,
        "message": sprintf("❌ Insecure crypto algorithm '%s' detected in %s", [algo.name, filename]),
        "detail": sprintf("%s Use modern alternatives like SHA-256, SHA-3, or AES.", [algo.message])
    }
}
