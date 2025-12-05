const SeverityBadge = ({ severity }) => {
  const colors = {
    high: "bg-red-100 text-red-800 border-red-300",
    medium: "bg-orange-100 text-orange-800 border-orange-300",
    low: "bg-yellow-100 text-yellow-800 border-yellow-300",
  };

  return (
    <span
      className={`px-2 py-1 rounded-full text-xs font-medium border ${
        colors[severity] || colors.low
      }`}
    >
      {severity?.toUpperCase() || "UNKNOWN"}
    </span>
  );
};
export default SeverityBadge;
