/** Structured, animated release notes shown inside the update dialog. */
import { useMemo } from "react";
import { formatReleaseDate, parseReleaseNotes } from "../releaseNotes";

/**
 * Turns the GitHub release body (the CHANGELOG section) into the "What's New"
 * layout: badge, headline, intro, and one animated card per section with an
 * emoji. Motion is decorative and disabled by `prefers-reduced-motion`.
 */
export function ReleaseNotes({
  body,
  tag,
  publishedAt,
}: {
  body: string | null;
  tag: string;
  publishedAt?: string | null;
}) {
  const notes = useMemo(() => parseReleaseNotes(body, tag), [body, tag]);
  const released = formatReleaseDate(publishedAt);
  const version = tag.trim().replace(/^v/i, "");

  return (
    <div className="release-notes" aria-label="Release notes">
      <div className="release-notes__head">
        <span className="release-notes__badge">
          <span aria-hidden="true">✨</span> Release notes
        </span>
        <span className="release-notes__version">Version {version}</span>
      </div>

      <h3 className="release-notes__title">What’s New</h3>
      {released ? <p className="release-notes__released">Released {released}</p> : null}

      <p className="release-notes__headline">{notes.headline}</p>
      {notes.intro ? <p className="release-notes__intro">{notes.intro}</p> : null}

      {notes.sections.length > 0 ? (
        <div className="release-notes__sections">
          {notes.sections.map((section, index) => (
            <section
              key={`${section.kind}-${index}`}
              className={`release-notes__section release-notes__section--${section.kind}`}
              style={{ animationDelay: `${90 + index * 70}ms` }}
            >
              <span className="release-notes__emoji" aria-hidden="true">
                {section.emoji}
              </span>
              <div>
                <h4>{section.label}</h4>
                <ul className="release-notes__items">
                  {section.items.map((item, itemIndex) => (
                    <li key={itemIndex} className="release-notes__item">
                      {item.title ? (
                        <>
                          <strong>{item.title}.</strong> {item.body}
                        </>
                      ) : (
                        item.body
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            </section>
          ))}
        </div>
      ) : notes.intro === "" ? (
        <p className="release-notes__empty">No release notes were published for this version.</p>
      ) : null}
    </div>
  );
}
