import React from "react";
import Spinner from "./Spinner";
const ModalLoader = () => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white p-6 rounded-lg shadow-xl">
        <div className="flex items-center gap-3">
          <Spinner />
          <span className="text-gray-700">Loading flow details...</span>
        </div>
      </div>
    </div>
  );
};

export default ModalLoader;
