"use client";

import { useEffect } from "react";

export function JsonModal({
  open,
  title,
  content,
  onClose,
}: {
  open: boolean;
  title: string;
  content: string;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!open) return;

    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }

    document.addEventListener("keydown", onKeyDown);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = prevOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  async function copy() {
    try {
      await navigator.clipboard.writeText(content);
    } catch {
      // ignore
    }
  }

  return (
    <div className="modalOverlay" onMouseDown={onClose}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="modalHeader">
          <div>
            <div className="modalTitle">{title}</div>
            <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
              Press Esc to close
            </div>
          </div>
          <div className="modalActions">
            <button className="btn" onClick={copy} type="button">
              Copy
            </button>
            <button className="btn primary" onClick={onClose} type="button">
              Close
            </button>
          </div>
        </div>
        <div className="modalBody">
          <pre className="codeBlock">{content}</pre>
        </div>
      </div>
    </div>
  );
}
