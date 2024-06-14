#!/bin/bash

# Check for xml output file 
if [ -f "$1" ]; then
    echo "$1 exists."
else 
    echo "$1 does not exist."
    exit 1
fi
# Parse the XML data
errors=$(xmllint --xpath 'string(//testsuite/@errors)' "$1")
failures=$(xmllint --xpath 'string(//testsuite/@failures)' "$1")
test_count=$(xmllint --xpath 'string(//testsuite/@tests)' "$1")

# Check if there are any errors or failures
if [[ $errors -gt 0 || $failures -gt 0 ]]; then
  echo "ERROR: Tests failed!"
  echo "$failures tests failed, $errors errors. out of $test_count tests"
  exit 1
else
  echo "SUCCESS: All tests passed!"
  echo "$test_count tests passed."
fi
