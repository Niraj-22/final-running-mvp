import React, { useState } from "react";
import FlowDetailModal from "./FlowDetailModal";
import { saveAs } from "file-saver";
import Spinner from "./components/spinner";
import {
  Shield,
  Upload,
  FileText,
  Download,
  AlertTriangle,
  Activity,
  Filter,
  Search,
  X,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import StatCard from "./components/StatCard";
import SeverityBadge from "./components/SeverityBadge";

const BACKEND = import.meta.env.VITE_API_URL || "http://localhost:8000";

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

export default function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [filterType, setFilterType] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedRows, setExpandedRows] = useState(new Set());

  const retryFetch = async (url, options, retries = 3) => {
    let attempt = 0;
    let backoff = 500;
    while (attempt <= retries) {
      try {
        const res = await fetch(url, options);
        if (!res.ok) {
          const errorData = await res.json().catch(() => ({}));
          throw new Error(errorData.detail || `Status ${res.status}`);
        }
        return res;
      } catch (e) {
        attempt++;
        if (attempt > retries) throw e;
        await sleep(backoff);
        backoff *= 2;
      }
    }
  };

  const handleUpload = async () => {
    setError("");
    if (!file) {
      setError("Please select a .pcap or .pcapng file");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    setLoading(true);
    try {
      const res = await retryFetch(
        `${BACKEND}/analyze`,
        {
          method: "POST",
          body: formData,
        },
        3
      );

      const data = await res.json();
      setResult(data);
      setError("");
    } catch (err) {
      setError(
        err.message || "Failed to analyze. Please check backend or try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const openFlow = async (flowId) => {
    setError("");
    setSelectedFlow({ loading: true, id: flowId });
    try {
      const res = await fetch(`${BACKEND}/flows/${flowId}`);
      if (!res.ok) throw new Error("Flow fetch failed");
      const data = await res.json();
      setSelectedFlow({ ...data, loading: false });
    } catch (e) {
      setSelectedFlow(null);
      setError("Failed to fetch flow details.");
    }
  };

  const exportData = async (fmt) => {
    if (!result) {
      setError("No analysis to export.");
      return;
    }
    try {
      const url =
        fmt === "pdf" ? `${BACKEND}/export-pdf` : `${BACKEND}/export/${fmt}`;
      const res = await fetch(url);
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const filename = `analysis_${Date.now()}.${fmt}`;
      saveAs(blob, filename);
    } catch (e) {
      setError("Export failed. Try again.");
    }
  };

  const clearAnalysis = async () => {
    try {
      await fetch(`${BACKEND}/analysis`, { method: "DELETE" });
      setResult(null);
      setFile(null);
      setError("");
      setFilterType("all");
      setSearchQuery("");
    } catch (e) {
      console.error("Failed to clear analysis:", e);
    }
  };

  const toggleRowExpansion = (idx) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(idx)) {
      newExpanded.delete(idx);
    } else {
      newExpanded.add(idx);
    }
    setExpandedRows(newExpanded);
  };

  // Filter and search suspicious items
  const filteredSuspicious = React.useMemo(() => {
    let items = result?.suspicious || [];

    // Filter by type
    if (filterType !== "all") {
      items = items.filter((s) => s.type === filterType);
    }

    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      items = items.filter((s) => {
        const identifier = s.type === "flow" ? s.id : s.domain || s.src || "";
        const reasons = s.reasons?.join(" ") || "";
        return (
          identifier.toLowerCase().includes(query) ||
          reasons.toLowerCase().includes(query) ||
          s.type.toLowerCase().includes(query)
        );
      });
    }

    return items;
  }, [result, filterType, searchQuery]);

  // Get unique types for filter
  const uniqueTypes = React.useMemo(() => {
    if (!result?.suspicious) return [];
    return [...new Set(result.suspicious.map((s) => s.type))];
  }, [result]);

  const formatBytes = (bytes) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  return (
    <div className="min-h-screen bg-linear-to-br from-gray-50 to-gray-100">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Shield className="w-6 h-6 text-blue-600" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">
                PCAP Traffic Analyzer
              </h1>
              <p className="text-sm text-gray-500">
                Network traffic analysis and threat detection
              </p>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Upload Section */}
        <div className="bg-white rounded-xl shadow-sm border p-6 mb-8">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-blue-50 rounded-lg">
              <Upload className="w-6 h-6 text-blue-600" />
            </div>
            <div className="flex-1">
              <h2 className="text-lg font-semibold text-gray-900 mb-2">
                Upload PCAP File
              </h2>
              <p className="text-sm text-gray-500 mb-4">
                Upload a .pcap or .pcapng file to analyze network traffic
                patterns and detect suspicious activity
              </p>

              <div className="flex items-center gap-4">
                <label className="flex-1 cursor-pointer">
                  <div className="border-2 border-dashed border-gray-300 rounded-lg p-4 hover:border-blue-400 transition-colors">
                    <input
                      type="file"
                      accept=".pcap,.pcapng"
                      className="hidden"
                      onChange={(e) => setFile(e.target.files[0])}
                    />
                    <div className="flex items-center justify-center gap-2 text-gray-600">
                      <FileText className="w-5 h-5" />
                      <span className="text-sm">
                        {file
                          ? file.name
                          : "Click to select file or drag & drop"}
                      </span>
                    </div>
                    {file && (
                      <p className="text-xs text-gray-400 text-center mt-2">
                        {formatBytes(file.size)}
                      </p>
                    )}
                  </div>
                </label>

                <button
                  onClick={handleUpload}
                  disabled={loading || !file}
                  className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors font-medium flex items-center gap-2"
                >
                  {loading ? (
                    <>
                      <Spinner />
                      <span>Analyzing...</span>
                    </>
                  ) : (
                    <>
                      <Activity className="w-4 h-4" />
                      <span>Analyze</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {error && (
            <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2">
              <AlertTriangle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
              <p className="text-sm text-red-800">{error}</p>
              <button onClick={() => setError("")} className="ml-auto">
                <X className="w-4 h-4 text-red-600" />
              </button>
            </div>
          )}
        </div>

        {/* Results Section */}
        {result && (
          <>
            {/* Statistics Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
              <StatCard
                icon={Activity}
                label="Total Flows"
                value={result.metrics?.flow_count || 0}
                color="blue"
              />
              <StatCard
                icon={AlertTriangle}
                label="Suspicious Items"
                value={result.metrics?.suspicious_count || 0}
                color="red"
              />
              <StatCard
                icon={FileText}
                label="Total Data"
                value={formatBytes(result.metrics?.total_bytes || 0)}
                color="green"
              />
              <StatCard
                icon={Shield}
                label="DNS Anomalies"
                value={result.metrics?.dns_anomalies || 0}
                color="purple"
              />
            </div>

            {/* Detailed Metrics */}
            {result.summary?.severity_breakdown && (
              <div className="bg-white rounded-xl shadow-sm border p-6 mb-8">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                  Threat Severity Breakdown
                </h3>
                <div className="grid grid-cols-3 gap-4">
                  <div className="text-center p-4 bg-red-50 rounded-lg border border-red-200">
                    <p className="text-3xl font-bold text-red-600">
                      {result.summary.severity_breakdown.high}
                    </p>
                    <p className="text-sm text-red-700 font-medium">
                      High Severity
                    </p>
                  </div>
                  <div className="text-center p-4 bg-orange-50 rounded-lg border border-orange-200">
                    <p className="text-3xl font-bold text-orange-600">
                      {result.summary.severity_breakdown.medium}
                    </p>
                    <p className="text-sm text-orange-700 font-medium">
                      Medium Severity
                    </p>
                  </div>
                  <div className="text-center p-4 bg-yellow-50 rounded-lg border border-yellow-200">
                    <p className="text-3xl font-bold text-yellow-600">
                      {result.summary.severity_breakdown.low}
                    </p>
                    <p className="text-sm text-yellow-700 font-medium">
                      Low Severity
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Suspicious Items Table */}
            <div className="bg-white rounded-xl shadow-sm border overflow-hidden">
              {/* Table Header with Controls */}
              <div className="p-6 border-b bg-gray-50">
                <div className="flex flex-wrap items-center justify-between gap-4">
                  <div>
                    <h2 className="text-xl font-semibold text-gray-900 flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5 text-orange-500" />
                      Suspicious Activity
                      <span className="text-sm font-normal text-gray-500">
                        ({filteredSuspicious.length} items)
                      </span>
                    </h2>
                  </div>

                  <div className="flex items-center gap-3">
                    {/* Search */}
                    <div className="relative">
                      <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                      <input
                        type="text"
                        placeholder="Search..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-9 pr-4 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                      />
                    </div>

                    {/* Filter */}
                    <div className="relative">
                      <Filter className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                      <select
                        value={filterType}
                        onChange={(e) => setFilterType(e.target.value)}
                        className="pl-9 pr-10 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none appearance-none bg-white"
                      >
                        <option value="all">All Types</option>
                        {uniqueTypes.map((type) => (
                          <option key={type} value={type}>
                            {type.toUpperCase()}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Export Buttons */}
                    <div className="flex gap-2">
                      <button
                        onClick={() => exportData("json")}
                        className="px-3 py-2 border rounded-lg text-sm hover:bg-gray-50 transition-colors flex items-center gap-2"
                        title="Export as JSON"
                      >
                        <Download className="w-4 h-4" />
                        JSON
                      </button>
                      <button
                        onClick={() => exportData("csv")}
                        className="px-3 py-2 border rounded-lg text-sm hover:bg-gray-50 transition-colors flex items-center gap-2"
                        title="Export as CSV"
                      >
                        <Download className="w-4 h-4" />
                        CSV
                      </button>
                      <button
                        onClick={() => exportData("pdf")}
                        className="px-3 py-2 border rounded-lg text-sm hover:bg-gray-50 transition-colors flex items-center gap-2"
                        title="Export as PDF"
                      >
                        <Download className="w-4 h-4" />
                        PDF
                      </button>
                    </div>

                    {/* Clear Button */}
                    <button
                      onClick={clearAnalysis}
                      className="px-3 py-2 bg-red-50 text-red-600 border border-red-200 rounded-lg text-sm hover:bg-red-100 transition-colors"
                      title="Clear Analysis"
                    >
                      Clear
                    </button>
                  </div>
                </div>
              </div>

              {/* Table */}
              {filteredSuspicious.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-gray-50 border-b">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Type
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Identifier
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Severity
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Metrics
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Details
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {filteredSuspicious.map((s, idx) => (
                        <React.Fragment key={idx}>
                          <tr className="hover:bg-gray-50 transition-colors">
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs font-medium">
                                {s.type.toUpperCase()}
                              </span>
                            </td>
                            <td className="px-6 py-4">
                              <div className="text-sm font-medium text-gray-900">
                                {s.type === "flow" ? (
                                  <code className="bg-gray-100 px-2 py-1 rounded text-xs">
                                    {s.id}
                                  </code>
                                ) : (
                                  <span>{s.domain || s.src || "N/A"}</span>
                                )}
                              </div>
                              {s.type === "flow" && (
                                <div className="text-xs text-gray-500 mt-1">
                                  {s.src} → {s.dst}
                                </div>
                              )}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <SeverityBadge severity={s.severity} />
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <div className="text-sm text-gray-900">
                                {s.bytes && (
                                  <div>📦 {formatBytes(s.bytes)}</div>
                                )}
                                {s.packets && <div>📨 {s.packets} packets</div>}
                                {s.count && <div>🔢 {s.count} events</div>}
                                {s.max_txt_bytes && (
                                  <div>📝 {s.max_txt_bytes}B TXT</div>
                                )}
                              </div>
                            </td>
                            <td className="px-6 py-4">
                              <button
                                onClick={() => toggleRowExpansion(idx)}
                                className="text-sm text-blue-600 hover:text-blue-800 flex items-center gap-1"
                              >
                                {expandedRows.has(idx) ? (
                                  <>
                                    <ChevronUp className="w-4 h-4" />
                                    Hide
                                  </>
                                ) : (
                                  <>
                                    <ChevronDown className="w-4 h-4" />
                                    Show ({s.reasons?.length || 0})
                                  </>
                                )}
                              </button>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              {s.type === "flow" && (
                                <button
                                  onClick={() => openFlow(s.id)}
                                  className="px-3 py-1 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors text-sm font-medium"
                                >
                                  View Flow
                                </button>
                              )}
                            </td>
                          </tr>

                          {/* Expanded Row */}
                          {expandedRows.has(idx) && (
                            <tr className="bg-gray-50">
                              <td colSpan="6" className="px-6 py-4">
                                <div className="space-y-2">
                                  <p className="text-sm font-medium text-gray-700">
                                    Reasons:
                                  </p>
                                  <ul className="space-y-1">
                                    {s.reasons?.map((r, i) => (
                                      <li
                                        key={i}
                                        className="text-sm text-gray-600 flex items-start gap-2"
                                      >
                                        <span className="text-orange-500 mt-1">
                                          •
                                        </span>
                                        <span>{r}</span>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-12 text-center">
                  <Shield className="w-16 h-16 text-gray-300 mx-auto mb-4" />
                  <p className="text-gray-500">
                    No suspicious activity found matching your filters
                  </p>
                </div>
              )}
            </div>
          </>
        )}
      </main>

      {/* Flow Detail Modal */}
      {selectedFlow && !selectedFlow.loading && (
        <FlowDetailModal
          flow={selectedFlow}
          onClose={() => setSelectedFlow(null)}
        />
      )}

      {/* Loading Modal */}
      {selectedFlow && selectedFlow.loading && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg shadow-xl">
            <div className="flex items-center gap-3">
              <Spinner />
              <span className="text-gray-700">Loading flow details...</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
