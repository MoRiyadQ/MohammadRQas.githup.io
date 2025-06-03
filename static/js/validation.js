function validateIP() {
    const target = document.getElementById('target').value.trim();
    const errorMessage = document.getElementById('error-message');
    
    // Regular expression to validate IP addresses and domain names
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const domainRegex = /^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$/;
    
    if (ipRegex.test(target) || domainRegex.test(target)) {
        errorMessage.style.display = 'none';
        document.getElementById("loading-spinner").style.display = 'block';
        return true;
    } else {
        errorMessage.style.display = 'block';
        document.getElementById("loading-spinner").style.display = 'none';
        return false;
    }
}

// Add event handlers when the document is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Set up exploit button event handlers
    document.querySelectorAll('.run-exploit-btn').forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.preventDefault();

            const target = button.getAttribute('data-target');
            const exploitPath = button.getAttribute('data-exploit');

            fetch("/run_exploit", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: new URLSearchParams({
                    target: target,
                    exploit_path: exploitPath
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    alert(data.message);
                    if (data.shell_url) {
                        document.getElementById('shell-interaction').style.display = 'block';
                        window.location.href = data.shell_url;  // Redirect to shell interaction
                    }
                }
            })
            .catch(error => {
                alert("An error occurred while executing the exploit.");
                console.error("Error:", error);
            });
        });
    });
});