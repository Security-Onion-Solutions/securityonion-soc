document.addEventListener('DOMContentLoaded', () => {
    const methodSelect = document.getElementById('es-method');
    const pathInput = document.getElementById('es-path');
    const requestBodyTextarea = document.getElementById('es-request');
    const responsePre = document.getElementById('es-response');
    const sendButton = document.getElementById('send-request-btn');

    // Set default path if empty
    if (!pathInput.value) {
        pathInput.value = '/_search';
    }
    // Set default body if empty
     if (!requestBodyTextarea.value) {
        requestBodyTextarea.value = JSON.stringify({ query: { match_all: {} } }, null, 2);
    }


    sendButton.addEventListener('click', async () => {
        const method = methodSelect.value;
        const path = pathInput.value.trim();
        let requestBody = requestBodyTextarea.value.trim();

        if (!path) {
            alert('Elasticsearch path cannot be empty.');
            return;
        }

        // Clear previous response and indicate loading
        responsePre.textContent = 'Sending request...';
        responsePre.style.color = '#555'; // Reset color

        // Basic validation for JSON body (if method requires one)
        let parsedBody = null;
        if (['POST', 'PUT'].includes(method) && requestBody) {
            try {
                parsedBody = JSON.parse(requestBody);
            } catch (e) {
                 responsePre.textContent = `Error parsing JSON request body:\n${e.message}`;
                 responsePre.style.color = 'red';
                return;
            }
        } else if (!['POST', 'PUT'].includes(method)) {
            // Ensure body is empty for methods that don't use it
            requestBody = '';
            parsedBody = null;
        }


        try {
            // Construct the request to our backend endpoint
            // This endpoint needs to be created on the Go server
            const backendUrl = '/api/v1/elasticsearch/proxy'; // Define the backend proxy endpoint URL

            const fetchOptions = {
                method: 'POST', // Always POST to our backend proxy
                headers: {
                    'Content-Type': 'application/json',
                    // Include CSRF token if necessary (assuming SOC uses CSRF protection)
                    // 'X-CSRF-Token': getCsrfToken(), // Function to get CSRF token
                },
                body: JSON.stringify({
                    method: method,
                    path: path,
                    body: requestBody ? parsedBody : null // Send parsed body or null
                }),
            };

            const response = await fetch(backendUrl, fetchOptions);

            // Check if the response from our backend is okay
            if (!response.ok) {
                 let errorText = `Backend Error: ${response.status} ${response.statusText}`;
                 try {
                     const errorData = await response.json();
                     errorText += `\n${JSON.stringify(errorData, null, 2)}`;
                 } catch (e) {
                     // If response is not JSON, try getting text
                     errorText += `\n${await response.text()}`;
                 }
                 throw new Error(errorText);
            }

            // Get the response data (which should be the response from Elasticsearch)
            const data = await response.json();

            // Display the Elasticsearch response nicely formatted
            responsePre.textContent = JSON.stringify(data, null, 2); // Pretty print JSON
            responsePre.style.color = 'black'; // Reset color on success


        } catch (error) {
            console.error('Error sending Elasticsearch request:', error);
            responsePre.textContent = `Error: ${error.message}`;
            responsePre.style.color = 'red';
        }
    });

    // Helper function placeholder for CSRF token retrieval if needed
    // function getCsrfToken() {
    //     // Implementation depends on how CSRF tokens are handled in SOC
    //     // e.g., read from a meta tag or a cookie
    //     return document.querySelector('meta[name="csrf-token"]')?.content || '';
    // }
});