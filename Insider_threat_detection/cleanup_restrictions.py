#!/usr/bin/env python3
"""
Clean up overly broad system restrictions
"""
from core.database import DatabaseManager

def cleanup_system_restrictions():
    """Remove system-level restrictions that cause false alerts"""
    db = DatabaseManager()
    
    # Remove overly broad system restrictions
    system_restrictions = [
        'C:\\Windows\\System32',
        'C:\\Windows\\System32\\config',
        'C:\\$Recycle.Bin'
    ]
    
    print("Cleaning up system restrictions...")
    
    for restriction in system_restrictions:
        query = "DELETE FROM restricted_resources WHERE resource_path = %s"
        result = db.execute_query(query, (restriction,))
        print(f"Removed restriction: {restriction}")
    
    # Add focused user document restrictions
    user_restrictions = [
        ('C:\\confidential', 'folder', 'no_access', 'Confidential documents'),
        ('C:\\sensitive', 'folder', 'no_access', 'Sensitive information'),
        ('C:\\TestRestricted', 'folder', 'no_access', 'Test restricted folder')
    ]
    
    print("\\nAdding focused restrictions...")
    
    for path, res_type, level, desc in user_restrictions:
        query = """
        INSERT INTO restricted_resources (resource_path, resource_type, restriction_level, description)
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE 
        restriction_level = VALUES(restriction_level),
        description = VALUES(description)
        """
        db.execute_query(query, (path, res_type, level, desc))
        print(f"Added restriction: {path}")
    
    # Show current restrictions
    print("\\nCurrent restrictions:")
    restrictions = db.get_restricted_resources()
    if restrictions:
        for r in restrictions:
            print(f"  - {r['resource_path']} ({r['restriction_level']})")
    else:
        print("  No restrictions found")

if __name__ == "__main__":
    cleanup_system_restrictions()