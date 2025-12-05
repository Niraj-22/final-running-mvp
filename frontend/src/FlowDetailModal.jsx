import React, { useState } from "react";
import {
  X,
  Info,
  Activity,
  Shield,
  Network,
  Database,
  ArrowRight,
  TrendingUp,
  Clock,
  Copy,
  Check,
  AlertTriangle,
} from "lucide-react";

const InfoRow = ({ label, value, copyable = false, field = "" }) => (
  <div className="flex justify-between items-center py-2 border-b border-gray-100">
    <span className="text-sm font-medium text-gray-600">{label}</span>
    <div className="flex items-center gap-2">
      <span className="text-sm text-gray-900 font-mono">{value ?? "N/A"}</span>
      {copyable && (
        <CopyButton text={value} field={field} copiedField copyToClipboard />
      )}
    </div>
  </div>
);

const CopyButton = ({ text, field, copyToClipboard, copiedField }) => (
  <button
    onClick={() => copyToClipboard(text, field)}
    className="p-1 hover:bg-gray-100 rounded transition-colors"
    title="Copy to clipboard"
  >
    {copiedField === field ? (
      <Check className="w-4 h-4 text-green-600" />
    ) : (
      <Copy className="w-4 h-4 text-gray-400" />
    )}
  </button>
);
const FlowDetailModal = ({ flow, onClose }) => {
  const [copiedField, setCopiedField] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");

  if (!flow) return null;
  const flowData = flow.flow || flow;
  const ft = flowData.five_tuple || {};

  const copyToClipboard = async (text, field) => {
    try {
      await navigator.clipboard.writeText(String(text ?? ""));
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      // ignore
    }
  };

  const formatBytes = (bytes) => {
    if (!bytes && bytes !== 0) return "N/A";
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const formatTimestamp = (ts) => {
    if (!ts) return "N/A";
    return new Date(ts * 1000).toLocaleString();
  };

  const formatDuration = (duration) => {
    if (duration == null) return "N/A";
    if (duration < 1) return `${(duration * 1000).toFixed(0)} ms`;
    if (duration < 60) return `${duration.toFixed(2)} s`;
    return `${(duration / 60).toFixed(2)} m`;
  };

  const calculateRate = () => {
    if (!flowData.duration || flowData.duration === 0) return "N/A";
    const bytesPerSec = (flowData.bytes || 0) / flowData.duration;
    return `${formatBytes(bytesPerSec)}/s`;
  };

  const analyzeTimeline = () => {
    if (!flowData.timeline || flowData.timeline.length === 0) return null;
    const totalBytes = flowData.timeline.reduce(
      (sum, t) => sum + (t.bytes || 0),
      0
    );
    const avgBytesPerSec = totalBytes / flowData.timeline.length;
    const maxBurst = Math.max(...flowData.timeline.map((t) => t.bytes || 0));
    return {
      avgBytesPerSec,
      maxBurst,
      burstRatio: avgBytesPerSec ? maxBurst / avgBytesPerSec : 0,
    };
  };

  const timelineStats = analyzeTimeline();

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b bg-linear-to-r from-blue-50 to-indigo-50">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-100 rounded-lg">
                <Network className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-gray-900">
                  Flow Details
                </h2>
                <p className="text-sm text-gray-600 font-mono">{flowData.id}</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <X className="w-5 h-5 text-gray-600" />
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="px-6 border-b bg-gray-50">
          <div className="flex gap-4">
            {[
              {
                id: "overview",
                label: "Overview",
                icon: Info,
              },
              {
                id: "timeline",
                label: "Timeline",
                icon: Activity,
              },
              {
                id: "analysis",
                label: "Analysis",
                icon: Shield,
              },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? "border-blue-600 text-blue-600 font-medium"
                    : "border-transparent text-gray-600 hover:text-gray-900"
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {activeTab === "overview" && (
            <div className="space-y-6">
              {/* Connection Info */}
              <div className="bg-white border rounded-lg p-4">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  <Network className="w-5 h-5 text-blue-600" />
                  Connection Information
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <InfoRow
                      label="Source IP"
                      value={ft.src || "N/A"}
                      copyable
                      field="src"
                    />
                    <InfoRow label="Source Port" value={ft.sport || "N/A"} />
                    <InfoRow label="Protocol" value={ft.protocol || "N/A"} />
                  </div>
                  <div className="space-y-1">
                    <InfoRow
                      label="Destination IP"
                      value={ft.dst || "N/A"}
                      copyable
                      field="dst"
                    />
                    <InfoRow
                      label="Destination Port"
                      value={ft.dport || "N/A"}
                    />
                    <InfoRow
                      label="Flow ID"
                      value={flowData.id}
                      copyable
                      field="id"
                    />
                  </div>
                </div>

                {/* Connection Diagram */}
                <div className="mt-6 p-4 bg-gray-50 rounded-lg">
                  <div className="flex items-center justify-center gap-4">
                    <div className="text-center">
                      <div className="w-16 h-16 bg-blue-100 rounded-lg flex items-center justify-center mb-2">
                        <span className="text-2xl">🖥️</span>
                      </div>
                      <p className="text-xs font-mono text-gray-600">
                        {ft.src}
                      </p>
                      <p className="text-xs text-gray-500">:{ft.sport}</p>
                    </div>

                    <div className="flex-1 flex items-center justify-center">
                      <ArrowRight className="w-8 h-8 text-blue-600" />
                    </div>

                    <div className="text-center">
                      <div className="w-16 h-16 bg-green-100 rounded-lg flex items-center justify-center mb-2">
                        <span className="text-2xl">🌐</span>
                      </div>
                      <p className="text-xs font-mono text-gray-600">
                        {ft.dst}
                      </p>
                      <p className="text-xs text-gray-500">:{ft.dport}</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Traffic Stats */}
              <div className="bg-white border rounded-lg p-4">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  <Database className="w-5 h-5 text-green-600" />
                  Traffic Statistics
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center p-4 bg-blue-50 rounded-lg">
                    <p className="text-2xl font-bold text-blue-600">
                      {formatBytes(flowData.bytes || 0)}
                    </p>
                    <p className="text-xs text-gray-600 mt-1">Total Bytes</p>
                  </div>
                  <div className="text-center p-4 bg-green-50 rounded-lg">
                    <p className="text-2xl font-bold text-green-600">
                      {flowData.packets || 0}
                    </p>
                    <p className="text-xs text-gray-600 mt-1">Packets</p>
                  </div>
                  <div className="text-center p-4 bg-purple-50 rounded-lg">
                    <p className="text-2xl font-bold text-purple-600">
                      {formatDuration(flowData.duration)}
                    </p>
                    <p className="text-xs text-gray-600 mt-1">Duration</p>
                  </div>
                  <div className="text-center p-4 bg-orange-50 rounded-lg">
                    <p className="text-2xl font-bold text-orange-600">
                      {calculateRate()}
                    </p>
                    <p className="text-xs text-gray-600 mt-1">Avg Rate</p>
                  </div>
                </div>
              </div>

              {/* Timing Info */}
              <div className="bg-white border rounded-lg p-4">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  <Clock className="w-5 h-5 text-purple-600" />
                  Timing Information
                </h3>
                <div className="space-y-1">
                  <InfoRow
                    label="Start Time"
                    value={formatTimestamp(flowData.start)}
                  />
                  <InfoRow
                    label="End Time"
                    value={formatTimestamp(flowData.end)}
                  />
                  <InfoRow
                    label="Duration"
                    value={formatDuration(flowData.duration)}
                  />
                </div>
              </div>

              {/* TCP Flags */}
              {flowData.tcp_flags && flowData.tcp_flags.length > 0 && (
                <div className="bg-white border rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    TCP Flags
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {flowData.tcp_flags.map((flag, idx) => (
                      <span
                        key={idx}
                        className="px-3 py-1 bg-indigo-100 text-indigo-800 rounded-full text-sm font-medium"
                      >
                        {flag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === "timeline" && (
            <div className="space-y-6">
              {/* Timeline Stats */}
              {timelineStats && (
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                    <p className="text-sm text-blue-600 font-medium">
                      Avg Transfer
                    </p>
                    <p className="text-2xl font-bold text-blue-700">
                      {formatBytes(timelineStats.avgBytesPerSec)}
                    </p>
                    <p className="text-xs text-blue-500">per second</p>
                  </div>
                  <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                    <p className="text-sm text-red-600 font-medium">
                      Max Burst
                    </p>
                    <p className="text-2xl font-bold text-red-700">
                      {formatBytes(timelineStats.maxBurst)}
                    </p>
                    <p className="text-xs text-red-500">in 1 second</p>
                  </div>
                  <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                    <p className="text-sm text-purple-600 font-medium">
                      Burst Ratio
                    </p>
                    <p className="text-2xl font-bold text-purple-700">
                      {(timelineStats.burstRatio || 0).toFixed(1)}x
                    </p>
                    <p className="text-xs text-purple-500">peak/average</p>
                  </div>
                </div>
              )}

              {/* Timeline Table */}
              <div className="bg-white border rounded-lg overflow-hidden">
                <div className="overflow-x-auto max-h-96">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 sticky top-0">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                          Timestamp
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                          Packets
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                          Bytes
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                          Activity
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200">
                      {(flowData.timeline || []).map((t, idx) => (
                        <tr key={idx} className="hover:bg-gray-50">
                          <td className="px-4 py-3 font-mono text-gray-600">
                            {formatTimestamp(t.ts)}
                          </td>
                          <td className="px-4 py-3 text-gray-900">{t.pkts}</td>
                          <td className="px-4 py-3 text-gray-900">
                            {formatBytes(t.bytes)}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <div className="flex-1 bg-gray-200 rounded-full h-2 max-w-[200px]">
                                <div
                                  className="bg-blue-600 h-2 rounded-full"
                                  style={{
                                    width: `${Math.min(
                                      100,
                                      timelineStats && timelineStats.maxBurst
                                        ? (t.bytes / timelineStats.maxBurst) *
                                            100
                                        : 0
                                    )}%`,
                                  }}
                                />
                              </div>
                              <TrendingUp className="w-4 h-4 text-blue-600" />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeTab === "analysis" && (
            <div className="space-y-6">
              {/* Payload Analysis */}
              {flowData.payload_analysis && (
                <div className="bg-white border rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                    <Shield className="w-5 h-5 text-green-600" />
                    Payload Analysis
                  </h3>

                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                      <div>
                        <p className="text-sm font-medium text-gray-700">
                          Average Entropy
                        </p>
                        <p className="text-xs text-gray-500 mt-1">
                          High entropy (&gt;7.5) suggests encryption or encoding
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-2xl font-bold text-gray-900">
                          {flowData.payload_analysis.avg_entropy || 0}
                        </p>
                        {flowData.payload_analysis.high_entropy && (
                          <span className="inline-flex items-center gap-1 text-xs text-red-600 font-medium mt-1">
                            <AlertTriangle className="w-3 h-3" />
                            High Entropy
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
                        <p className="text-sm text-blue-600 font-medium">
                          Samples Analyzed
                        </p>
                        <p className="text-2xl font-bold text-blue-700">
                          {flowData.payload_analysis.sample_count || 0}
                        </p>
                      </div>
                      <div className="p-4 bg-purple-50 border border-purple-200 rounded-lg">
                        <p className="text-sm text-purple-600 font-medium">
                          HTTP POST
                        </p>
                        <p className="text-2xl font-bold text-purple-700">
                          {flowData.has_http_post ? "Yes" : "No"}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Security Assessment */}
              <div className="bg-white border rounded-lg p-4">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-orange-600" />
                  Security Assessment
                </h3>

                <div className="space-y-3">
                  <div className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                    <Info className="w-5 h-5 text-blue-600 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        Data Volume
                      </p>
                      <p className="text-xs text-gray-600 mt-1">
                        {flowData.bytes > 50000
                          ? "Large data transfer detected - potential data exfiltration"
                          : "Normal data volume"}
                      </p>
                    </div>
                  </div>

                  {flowData.payload_analysis?.high_entropy && (
                    <div className="flex items-start gap-3 p-3 bg-red-50 rounded-lg border border-red-200">
                      <AlertTriangle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
                      <div>
                        <p className="text-sm font-medium text-red-900">
                          High Entropy Data
                        </p>
                        <p className="text-xs text-red-700 mt-1">
                          Data appears to be encrypted or encoded - requires
                          further investigation
                        </p>
                      </div>
                    </div>
                  )}

                  {flowData.has_http_post && (
                    <div className="flex items-start gap-3 p-3 bg-yellow-50 rounded-lg border border-yellow-200">
                      <Info className="w-5 h-5 text-yellow-600 shrink-0 mt-0.5" />
                      <div>
                        <p className="text-sm font-medium text-yellow-900">
                          HTTP POST Detected
                        </p>
                        <p className="text-xs text-yellow-700 mt-1">
                          Flow contains HTTP POST request - verify if data
                          upload is legitimate
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t bg-gray-50 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition-colors font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default FlowDetailModal;
