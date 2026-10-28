// HTTPS URLs for the deployed applications
const ADAPTIVE_APP_URL =
  "https://staging.d2bfc3u89gtt0g.amplifyapp.com/adaptive-ui/";

const QUISHING_APP_URL =
  "https://staging.d2bfc3u89gtt0g.amplifyapp.com/quishing/";

document.getElementById("adaptiveBtn").addEventListener("click", () => {
  window.location.href = ADAPTIVE_APP_URL;
});

document.getElementById("quishingBtn").addEventListener("click", () => {
  window.location.href = QUISHING_APP_URL;
});
