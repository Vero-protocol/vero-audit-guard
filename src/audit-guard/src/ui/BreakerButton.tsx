// src/audit-guard/src/ui/BreakerButton.tsx
import React, { useState } from "react";
import "./BreakerButton.css";
import { triggerCircuitBreaker } from "../irps";

export const BreakerButton: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const handleClick = async () => {
    if (loading) return;
    setLoading(true);
    try {
      await triggerCircuitBreaker();
      alert("Circuit breaker triggered – protocol paused.");
    } catch (e) {
      console.error(e);
      alert("Failed to trigger circuit breaker.");
    } finally {
      setLoading(false);
    }
  };
  return (
    <button className="breaker-button" onClick={handleClick} disabled={loading}>
      {loading ? "Processing…" : "Emergency Circuit Breaker"}
    </button>
  );
};

export default BreakerButton;
