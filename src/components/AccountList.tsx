/**
 * Left pane: the whole directory, grouped by service.
 *
 * One search box and one add row at the top, then every account under the
 * service it belongs to. No filters, no side panels — the point is to see
 * which accounts you have for a service at a glance.
 */
import { useState } from "react";
import { Plus, Search } from "lucide-react";
import type { Account, AccountId } from "../domain";
import { groupAccountsByService, serviceTint } from "../display";

export function AccountList({
  accounts,
  serviceIcons,
  selectedId,
  query,
  onQuery,
  onSelect,
  onAdd,
  addError,
}: {
  /** Already filtered by search. */
  accounts: readonly Account[];
  /** Optional per-service pictures, keyed by the exact service label. */
  serviceIcons: Readonly<Record<string, string>>;
  selectedId: AccountId | null;
  query: string;
  onQuery: (value: string) => void;
  onSelect: (accountId: AccountId) => void;
  onAdd: (name: string, service: string) => boolean;
  addError: string | null;
}) {
  const [draftName, setDraftName] = useState("");
  const [draftService, setDraftService] = useState("");

  const groups = groupAccountsByService(accounts);
  const total = accounts.length;
  const services = [...new Set(accounts.map((account) => account.service).filter((service) => service !== ""))].sort(
    (left, right) => left.localeCompare(right, undefined, { sensitivity: "base" }),
  );

  function submit() {
    if (onAdd(draftName, draftService)) {
      setDraftName("");
      setDraftService("");
    }
  }

  return (
    <section className="account-list-pane" aria-label="Accounts">
      <header className="list-head">
        <div className="list-head__title">
          <h2>Accounts</h2>
          <p>
            {total} account{total === 1 ? "" : "s"} · {groups.length} service
            {groups.length === 1 ? "" : "s"}
          </p>
        </div>

        <div className="side-search">
          <Search />
          <input
            type="text"
            placeholder="Search name, service or tag…"
            value={query}
            onChange={(event) => onQuery(event.target.value)}
            aria-label="Search accounts"
          />
        </div>

        <form
          className="add-account"
          onSubmit={(event) => {
            event.preventDefault();
            submit();
          }}
        >
          <input
            type="text"
            placeholder="New account name"
            value={draftName}
            onChange={(event) => setDraftName(event.target.value)}
            aria-label="New account name"
          />
          <input
            type="text"
            className="add-account__service"
            placeholder="Service"
            value={draftService}
            list="add-service-options"
            onChange={(event) => setDraftService(event.target.value)}
            aria-label="New account service"
          />
          <datalist id="add-service-options">
            {services.map((service) => (
              <option key={service} value={service} />
            ))}
          </datalist>
          <button type="submit" className="add-account__submit" aria-label="Add account">
            <Plus /> Add
          </button>
        </form>
        {addError ? <p className="create-form__error">{addError}</p> : null}
      </header>

      {total > 0 ? (
        <div className="account-groups">
          {groups.map((group) => (
            <section className="service-group" key={group.service || "__other"} aria-label={`Service ${group.label}`}>
              <h3 className="service-group__title">
                {serviceIcons[group.service] ? (
                  <img
                    className="service-dot service-dot--image"
                    src={serviceIcons[group.service]}
                    alt=""
                  />
                ) : (
                  <span className={`service-dot service-dot--${serviceTint(group.service)}`} aria-hidden="true" />
                )}
                <span>{group.label}</span>
                <span className="service-group__count">{group.accounts.length}</span>
              </h3>
              <ul className="account-list">
                {group.accounts.map((account) => (
                  <li key={account.id}>
                    <button
                      type="button"
                      className="account-row"
                      aria-pressed={selectedId === account.id}
                      onClick={() => onSelect(account.id)}
                    >
                      <span className="account-row__text">
                        <b>{account.name}</b>
                        <small>
                          {account.fields.length} field{account.fields.length === 1 ? "" : "s"}
                          {account.tags.length > 0 ? ` · ${account.tags.join(", ")}` : ""}
                        </small>
                      </span>
                      {account.fields.length === 0 && account.tags.length === 0 ? (
                        <span className="account-row__badge">empty</span>
                      ) : null}
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      ) : (
        <div className="empty account-list__empty">
          <Search />
          <p>
            <b>{query.trim() === "" ? "No accounts yet" : "Nothing matches"}</b>
            {query.trim() === "" ? "Add your first account above." : `No account matches “${query.trim()}”.`}
          </p>
        </div>
      )}
    </section>
  );
}
