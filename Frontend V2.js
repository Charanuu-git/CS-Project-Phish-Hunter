const imageInput = document.getElementById('imageInput');
const uploadForm = document.getElementById('uploadForm');
const analyzeBtn = document.getElementById('analyzeBtn');
const resultDiv = document.getElementById('result');

imageInput.addEventListener('change', function() {
  analyzeBtn.disabled = !imageInput.files.length;
});

uploadForm.addEventListener('submit', async function(e) {
  e.preventDefault();
  if (!imageInput.files.length) {
    resultDiv.textContent = "Please select an image file.";
    return;
  }
  const imageFile = imageInput.files[0];
  resultDiv.textContent = 'Analyzing...';

  const formData = new FormData();
  formData.append('image', imageFile);

  try {
    const response = await fetch('/api/analyze-email', {
      method: 'POST',
      body: formData,
    });
    const data = await response.json();

    // Format the output
    let output = `~~${data.riskScore}%\n\n`;
    if (data.result.header) {
      output += `Header:\n  Suspicious: ${data.result.header.suspicious}\n`;
      if (data.result.header.reason) output += `  Reason: ${data.result.header.reason}\n`;
    }
    if (data.result.sender) {
      output += `Sender:\n  Email: ${data.result.sender.email}\n  Suspicious: ${data.result.sender.suspicious}\n`;
      if (data.result.sender.reason) output += `  Reason: ${data.result.sender.reason}\n`;
    }
    resultDiv.textContent = output;
  } catch (err) {
    resultDiv.textContent = 'Error analyzing image.';
  }
});
