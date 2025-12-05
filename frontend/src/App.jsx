import React, { useState } from "react";
import FlowDetailModal from "./FlowDetailModal";
import { saveAs } from "file-saver";
import { sleep } from "./lib/utils";
import Header from "./components/Header";
import ModalLoader from "./components/ModalLoader";
import UploadSection from "./components/UploadSection";
import ResultSection from "./components/ResultSection";
const BACKEND = import.meta.env.VITE_API_URL || "http://localhost:8000";

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
      console.log(e);
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
      console.log(e);
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

  const uniqueTypes = React.useMemo(() => {
    if (!result?.suspicious) return [];
    return [...new Set(result.suspicious.map((s) => s.type))];
  }, [result]);

  return (
    <div className="min-h-screen bg-linear-to-br from-gray-50 to-gray-100">
      <Header />

      <main className="max-w-7xl mx-auto px-6 py-8">
        <UploadSection
          error={error}
          file={file}
          handleUpload={handleUpload}
          loading={loading}
          setError={setError}
          setFile={setFile}
        />

        {result && (
          <ResultSection
            clearAnalysis={clearAnalysis}
            expandedRows={expandedRows}
            exportData={exportData}
            filterType={filterType}
            filteredSuspicious={filteredSuspicious}
            openFlow={openFlow}
            result={result}
            searchQuery={searchQuery}
            setFilterType={setFilterType}
            setSearchQuery={setSearchQuery}
            toggleRowExpansion={toggleRowExpansion}
            uniqueTypes={uniqueTypes}
          />
        )}
      </main>

      {selectedFlow && !selectedFlow.loading && (
        <FlowDetailModal
          flow={selectedFlow}
          onClose={() => setSelectedFlow(null)}
        />
      )}

      {selectedFlow && selectedFlow.loading && <ModalLoader />}
    </div>
  );
}
