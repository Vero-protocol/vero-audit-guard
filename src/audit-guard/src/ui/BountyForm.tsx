// src/audit-guard/src/ui/BountyForm.tsx

import React, { useState } from "react";
import "./BountyForm.css";
import { submitBounty, BountyPayload } from "../bounty";

export const BountyForm: React.FC = () => {
  const [formData, setFormData] = useState<BountyPayload>({
    name: "",
    email: "",
    description: "",
    severity: "Low",
    timestamp: "",
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string>("");

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return;
    setLoading(true);
    setMessage("");
    try {
      await submitBounty(formData);
      setMessage("✅ Bounty submission recorded successfully.");
      setFormData({ name: "", email: "", description: "", severity: "Low", timestamp: "" });
    } catch (err) {
      console.error(err);
      setMessage("❌ Failed to record bounty submission.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form className="bounty-form" onSubmit={handleSubmit}>
      <h2>🔍 Submit a Bug Bounty</h2>
      <input name="name" placeholder="Your Name" value={formData.name} onChange={handleChange} required />
      <input type="email" name="email" placeholder="Email" value={formData.email} onChange={handleChange} required />
      <select name="severity" value={formData.severity} onChange={handleChange}>
        <option value="Low">Low</option>
        <option value="Medium">Medium</option>
        <option value="High">High</option>
        <option value="Critical">Critical</option>
      </select>
      <textarea
        name="description"
        placeholder="Describe the vulnerability..."
        rows={5}
        value={formData.description}
        onChange={handleChange}
        required
      />
      <button type="submit" disabled={loading}>
        {loading ? "Submitting…" : "Submit Bounty"}
      </button>
      {message && <p>{message}</p>}
    </form>
  );
};

export default BountyForm;
