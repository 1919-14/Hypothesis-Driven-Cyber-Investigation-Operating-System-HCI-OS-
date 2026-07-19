import React from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

/**
 * ErrorBoundary — wraps any subtree and catches render errors so the rest
 * of the app continues to work. Each panel that might fail should be wrapped
 * individually so only that panel shows the fallback, not the whole page.
 */
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error("[HCI-OS ErrorBoundary]", error, info);
  }

  reset() {
    this.setState({ hasError: false, error: null });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="panel px-5 py-6 flex flex-col items-center gap-3 text-center">
          <AlertTriangle size={24} className="text-amber-500" />
          <div className="font-head font-bold text-[14px]">
            {this.props.title ?? "Component Error"}
          </div>
          <div className="text-[12px] text-[var(--hci-text-3)] max-w-[340px] leading-relaxed">
            {this.state.error?.message ?? "An unexpected rendering error occurred."}
            {" "}Data will be retried automatically.
          </div>
          <button
            className="btn btn-outline btn-sm mt-1"
            onClick={() => this.reset()}
          >
            <RefreshCw size={12} /> Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;
