import {
  Activity,
  AlertTriangle,
  AlertTriangleIcon,
  ChevronDown,
  ChevronUp,
  Download,
  FileText,
  Filter,
  Search,
  Shield,
} from "lucide-react";
import React from "react";
import { formatBytes } from "../lib/utils";
import StatCard from "./StatCard";
import SeverityBadge from "./SeverityBadge";

const ResultSection = ({
  result,
  filteredSuspicious,
  searchQuery,
  setFilterType,
  setSearchQuery,
  filterType,
  uniqueTypes,
  exportData,
  clearAnalysis,
  expandedRows,
  toggleRowExpansion,
  openFlow,
}) => {
  return (
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
              <p className="text-sm text-red-700 font-medium">High Severity</p>
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
                <AlertTriangleIcon className="w-5 h-5 text-orange-500" />
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
                          {s.bytes && <div>📦 {formatBytes(s.bytes)}</div>}
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
  );
};

export default ResultSection;
