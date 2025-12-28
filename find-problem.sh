#!/bin/bash

echo "=== Finding problematic query files ==="
echo ""

# Test each query file individually
for query_file in database/queries/**/*.sql; do
    # Skip if file doesn't exist
    [ -f "$query_file" ] || continue
    
    echo -n "Testing: $query_file ... "
    
    # Get the module path
    module=$(dirname "$query_file" | sed 's|database/queries/||')
    
    # Create temporary config
    cat > /tmp/sqlc-temp.yaml << EOF
version: "2"
sql:
  - engine: "postgresql"
    schema: "database/schemas/$module/*.sql"
    queries: "$query_file"
    gen:
      go:
        package: "sqlc"
        out: "/tmp/sqlc-test-output"
        sql_package: "pgx/v5"
EOF
    
    # Test the file
    if sqlc generate -f /tmp/sqlc-temp.yaml 2>/tmp/sqlc-error.log; then
        echo "✓ OK"
    else
        echo "✗ FAILED"
        echo ""
        echo "===================================="
        echo "PROBLEM FOUND IN: $query_file"
        echo "===================================="
        echo ""
        echo "File contents:"
        cat "$query_file"
        echo ""
        echo "Error output:"
        cat /tmp/sqlc-error.log
        echo ""
        exit 1
    fi
done

echo ""
echo "All query files passed individual tests!"
echo "The issue might be with combined file processing."

# Cleanup
rm -f /tmp/sqlc-temp.yaml
rm -rf /tmp/sqlc-test-output