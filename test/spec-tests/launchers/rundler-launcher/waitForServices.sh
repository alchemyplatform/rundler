#!/bin/bash

# Define the service and port combinations to check
services=("rundler" "geth")
endpoints=("/health" "") # Specify the endpoint for service1 and leave service2 empty
ports=(3000 8545)

# Set the total duration in seconds
total_duration=30

# Initialize flags to track service status
rundler_active=false
geth_active=false

# Loop for the total duration with a 1-second interval
for ((i=0; i<total_duration; i++)); do
  echo "Checking services at $(date)"

  # Check if both services are active
  if [ "${rundler_active}" = true ] && [ "${geth_active}" = true ]; then
    echo "Both services are active. Exiting."
    exit 0
  fi

  # Loop through the services and ports
  for ((j=0; j<${#services[@]}; j++)); do
    service="${services[j]}"
    endpoint="${endpoints[j]}"
    port="${ports[j]}"

    # Construct the URL based on whether an endpoint is specified
    if [ -n "$endpoint" ]; then
      url="http://127.0.0.1:${port}${endpoint}"
    else
      url="http://127.0.0.1:${port}"
    fi

    # Use curl to check if the service is active
    if curl -s --head "${url}" >/dev/null; then
      echo "${service} on port ${port} is active."

      # Set the flag for the corresponding service to true
      if [ "${service}" == "rundler" ]; then
        rundler_active=true
      elif [ "${service}" == "geth" ]; then
        geth_active=true
      fi
    fi
  done

  # Sleep for 1 second before the next iteration
  sleep 1
done

# If we reach this point, it means both services were not active within the 30-second window
echo "Both services were not active within the 30-second window. Exiting with failure."
exit 1
