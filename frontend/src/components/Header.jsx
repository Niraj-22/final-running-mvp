import { Shield } from "lucide-react";
import React from "react";

const Header = () => {
  return (
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
  );
};

export default Header;
