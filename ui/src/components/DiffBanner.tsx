import type { LastDiff, TransitionKind } from "../types";
import { fmtTime } from "../api";

const MARKS: Record<TransitionKind, string> = {
  new: "+",
  changed: "~",
  gone: "−",
  returned: "↩",
};

export default function DiffBanner({ diff }: { diff: LastDiff }) {
  const counts = diff.transitions.reduce<Record<string, number>>((acc, t) => {
    acc[t.kind] = (acc[t.kind] ?? 0) + 1;
    return acc;
  }, {});
  const summary =
    diff.transitions.length === 0
      ? "No changes since the last scan."
      : Object.entries(counts)
          .map(([kind, count]) => `${count} ${kind}`)
          .join(" · ");

  return (
    <div className={diff.partial ? "diff partial" : "diff"}>
      <div className="diff-summary">
        <span className="diff-title">Last scan {fmtTime(diff.finished_at)}</span>
        <span className="diff-count">{summary}</span>
        {diff.partial ? (
          <span className="badge partial-badge" title="A partial scan never reports devices as gone">
            partial — “gone” suppressed
          </span>
        ) : (
          <span className="badge ok">complete</span>
        )}
      </div>
      {diff.partial && (
        <ul className="partial-reasons">
          {diff.partial_reasons.map((r, i) => (
            <li key={i}>
              {r.strategy}: {r.reason}
            </li>
          ))}
        </ul>
      )}
      {diff.transitions.length > 0 && (
        <ul className="transitions">
          {diff.transitions.map((t, i) => (
            <li key={i} className={t.kind}>
              <span className="mark">{MARKS[t.kind]}</span> {t.device_display}
              {t.unstable_identity && (
                <span className="badge randomised" title="This device changes its MAC by design. It cannot be followed across rotations, so it is never reported gone. Give it a name to make it trackable.">
                  randomised identity
                </span>
              )}
              {t.changes.length > 0 && (
                <span className="muted">
                  {" "}
                  ({t.changes.map((c) => `${c.field}: ${c.from ?? "∅"}→${c.to ?? "∅"}`).join(", ")})
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      {diff.transitions.some((t) => t.unstable_identity) && (
        <p className="muted small randomised-note">
          Devices marked <em>randomised identity</em> change their MAC by design.
          Modern IP Scanner cannot follow them across rotations, so it never reports them
          gone. Give one a name to make it trackable.
        </p>
      )}
    </div>
  );
}
