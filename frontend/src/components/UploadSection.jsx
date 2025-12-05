import { Activity } from "react";
import { formatBytes } from "../lib/utils";
import { FileText, Upload } from "lucide-react";
import Spinner from "./Spinner";
const UploadSection = ({
  setFile,
  file,
  handleUpload,
  loading,
  error,
  setError,
}) => {
  return (
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
            Upload a .pcap or .pcapng file to analyze network traffic patterns
            and detect suspicious activity
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
                    {file ? file.name : "Click to select file or drag & drop"}
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
  );
};

export default UploadSection;
