export const formatBytes = (bytes) => {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

export const formatTimestamp = (ts) => {
  if (!ts) return "N/A";
  return new Date(ts * 1000).toLocaleString();
};

export const formatDuration = (duration) => {
  if (duration == null) return "N/A";
  if (duration < 1) return `${(duration * 1000).toFixed(0)} ms`;
  if (duration < 60) return `${duration.toFixed(2)} s`;
  return `${(duration / 60).toFixed(2)} m`;
};
