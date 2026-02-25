#!/usr/bin/env python3
"""
PQC Test Script - Verify quantum-safe encryption functionality
"""

from pqc_handler import pqc_handler

def test_pqc_functionality():
    print("Testing Post-Quantum Cryptography Implementation")
    print("=" * 60)
    
    # Test 1: Gmail Credential Encryption
    print("\n1. Testing Gmail Credential Encryption:")
    test_password = "tddj aptv vqms zoqc"
    
    encrypted_creds = pqc_handler.encrypt_gmail_credentials(test_password)
    if encrypted_creds:
        print(f"   SUCCESS: Encryption successful: {encrypted_creds['encryption_method']}")
        
        # Test decryption
        decrypted_password = pqc_handler.decrypt_gmail_credentials(encrypted_creds)
        if decrypted_password == test_password:
            print("   SUCCESS: Decryption successful - passwords match")
        else:
            print("   FAILED: Decryption failed - passwords don't match")
    else:
        print("   FAILED: Encryption failed")
    
    # Test 2: Email Content Encryption
    print("\n2. Testing Email Content Encryption:")
    test_subject = "Test Email Subject"
    test_body = "This is a test email body with sensitive content."
    
    encrypted_content = pqc_handler.encrypt_email_content(test_body, test_subject)
    if encrypted_content:
        print(f"   SUCCESS: Content encryption successful: {encrypted_content['encryption_method']}")
        
        # Test decryption
        decrypted_content = pqc_handler.decrypt_email_content(encrypted_content)
        if (decrypted_content['body'] == test_body and 
            decrypted_content['subject'] == test_subject):
            print("   SUCCESS: Content decryption successful - content matches")
        else:
            print("   FAILED: Content decryption failed - content doesn't match")
    else:
        print("   FAILED: Content encryption failed")
    
    # Test 3: Session Token Generation
    print("\n3. Testing Secure Session Tokens:")
    test_user_id = 123
    
    token = pqc_handler.generate_secure_session_token(test_user_id)
    if token:
        print("   SUCCESS: Session token generated successfully")
        
        # Test verification
        is_valid = pqc_handler.verify_session_token(token, test_user_id)
        if is_valid:
            print("   SUCCESS: Session token verification successful")
        else:
            print("   FAILED: Session token verification failed")
    else:
        print("   FAILED: Session token generation failed")
    
    print("\n" + "=" * 60)
    print("PQC Test Complete - System ready for quantum-safe operations!")

if __name__ == "__main__":
    test_pqc_functionality()