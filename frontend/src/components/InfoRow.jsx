import React from "react";
const InfoRow = ({ label, value }) => (
  <div className="flex justify-between items-center py-2 border-b border-gray-100">
    <span className="text-sm font-medium text-gray-600">{label}</span>
    <div className="flex items-center gap-2">
      <span className="text-sm text-gray-900 font-mono">{value ?? "N/A"}</span>
    </div>
  </div>
);

export default InfoRow;
