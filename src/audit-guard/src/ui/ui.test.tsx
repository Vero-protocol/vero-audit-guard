/** @jest-environment jsdom */

import "@testing-library/jest-dom";
import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { BountyForm } from "./BountyForm";
import { BreakerButton } from "./BreakerButton";
import { submitBounty } from "../bounty";
import { triggerCircuitBreaker } from "../irps";

jest.mock("../bounty", () => ({
  submitBounty: jest.fn(),
}));
jest.mock("../irps", () => ({
  triggerCircuitBreaker: jest.fn(),
}));

const mockSubmitBounty = submitBounty as jest.MockedFunction<typeof submitBounty>;
const mockTriggerCircuitBreaker = triggerCircuitBreaker as jest.MockedFunction<typeof triggerCircuitBreaker>;

describe("BountyForm", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSubmitBounty.mockResolvedValue(undefined);
  });

  it("renders required fields and the default severity", () => {
    render(<BountyForm />);

    expect(screen.getByPlaceholderText("Your Name")).toBeRequired();
    expect(screen.getByPlaceholderText("Email")).toBeRequired();
    expect(screen.getByPlaceholderText("Describe the vulnerability...")).toBeRequired();
    expect(screen.getByRole("combobox")).toHaveValue("Low");
    expect(screen.getByRole("button", { name: "Submit Bounty" })).toBeEnabled();
  });

  it("submits the form and resets fields after success", async () => {
    render(<BountyForm />);

    fireEvent.change(screen.getByPlaceholderText("Your Name"), { target: { value: "Ayaan" } });
    fireEvent.change(screen.getByPlaceholderText("Email"), { target: { value: "ayaan@example.com" } });
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "High" } });
    fireEvent.change(screen.getByPlaceholderText("Describe the vulnerability..."), {
      target: { value: "Unexpected signer detected" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Submit Bounty" }));

    await waitFor(() => expect(mockSubmitBounty).toHaveBeenCalledWith({
      name: "Ayaan",
      email: "ayaan@example.com",
      description: "Unexpected signer detected",
      severity: "High",
      timestamp: "",
    }));
    expect(await screen.findByText("✅ Bounty submission recorded successfully.")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Your Name")).toHaveValue("");
    expect(screen.getByPlaceholderText("Email")).toHaveValue("");
    expect(screen.getByPlaceholderText("Describe the vulnerability...")).toHaveValue("");
    expect(screen.getByRole("combobox")).toHaveValue("Low");
  });

  it("shows a failure message when submission fails", async () => {
    mockSubmitBounty.mockRejectedValueOnce(new Error("write failed"));
    render(<BountyForm />);

    fireEvent.change(screen.getByPlaceholderText("Your Name"), { target: { value: "Ayaan" } });
    fireEvent.change(screen.getByPlaceholderText("Email"), { target: { value: "ayaan@example.com" } });
    fireEvent.change(screen.getByPlaceholderText("Describe the vulnerability..."), {
      target: { value: "Failed submission" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Submit Bounty" }));

    expect(await screen.findByText("❌ Failed to record bounty submission.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Submit Bounty" })).toBeEnabled();
  });

  it("disables the submit button while the request is pending", async () => {
    let resolveSubmission: () => void = () => undefined;
    mockSubmitBounty.mockImplementationOnce(() => new Promise<void>((resolve) => {
      resolveSubmission = resolve;
    }));
    render(<BountyForm />);

    fireEvent.change(screen.getByPlaceholderText("Your Name"), { target: { value: "Ayaan" } });
    fireEvent.change(screen.getByPlaceholderText("Email"), { target: { value: "ayaan@example.com" } });
    fireEvent.change(screen.getByPlaceholderText("Describe the vulnerability..."), {
      target: { value: "Pending submission" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Submit Bounty" }));

    expect(await screen.findByRole("button", { name: "Submitting…" })).toBeDisabled();
    resolveSubmission();
    await waitFor(() => expect(screen.getByRole("button", { name: "Submit Bounty" })).toBeEnabled());
  });
});

describe("BreakerButton", () => {
  const alertSpy = jest.spyOn(window, "alert").mockImplementation(() => undefined);

  beforeEach(() => {
    jest.clearAllMocks();
    mockTriggerCircuitBreaker.mockResolvedValue(undefined);
  });

  afterAll(() => {
    alertSpy.mockRestore();
  });

  it("triggers the circuit breaker and confirms success", async () => {
    render(<BreakerButton />);

    fireEvent.click(screen.getByRole("button", { name: "Emergency Circuit Breaker" }));

    await waitFor(() => expect(mockTriggerCircuitBreaker).toHaveBeenCalledTimes(1));
    expect(alertSpy).toHaveBeenCalledWith("Circuit breaker triggered – protocol paused.");
    expect(screen.getByRole("button", { name: "Emergency Circuit Breaker" })).toBeEnabled();
  });

  it("shows an error and restores the button when triggering fails", async () => {
    mockTriggerCircuitBreaker.mockRejectedValueOnce(new Error("breaker failed"));
    render(<BreakerButton />);

    fireEvent.click(screen.getByRole("button", { name: "Emergency Circuit Breaker" }));

    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith("Failed to trigger circuit breaker."));
    expect(screen.getByRole("button", { name: "Emergency Circuit Breaker" })).toBeEnabled();
  });

  it("disables the button while the breaker request is pending", async () => {
    let resolveBreaker: () => void = () => undefined;
    mockTriggerCircuitBreaker.mockImplementationOnce(() => new Promise<void>((resolve) => {
      resolveBreaker = resolve;
    }));
    render(<BreakerButton />);

    fireEvent.click(screen.getByRole("button", { name: "Emergency Circuit Breaker" }));
    expect(await screen.findByRole("button", { name: "Processing…" })).toBeDisabled();
    resolveBreaker();
    await waitFor(() => expect(screen.getByRole("button", { name: "Emergency Circuit Breaker" })).toBeEnabled());
  });
});
