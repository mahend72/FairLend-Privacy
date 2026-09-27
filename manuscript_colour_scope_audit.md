# Manuscript Colour-Scope Audit and Repair

Scope: a formatting-only repair of the `\color{red}`/`\color{black}` imbalance identified in the final Reviewer #2 evidence-consistency audit. No scientific content, equations, numerical values, citations, reviewer-response wording, algorithms, tables, or figures were changed. This is a standalone, independently revertible commit.

---

## 1. Every colour command in `manucript.tex`

A full-document search found exactly nine colour-related commands, no `\textcolor{...}`, `\pagecolor{...}`, or `\definecolor{...}` anywhere:

| Line (before repair) | Command | Context |
|---|---|---|
| 164 | `\color{red}` | Start of `\subsection{Contributions}` |
| 185 | `\color{black}` | End of the Contributions subsection's closing paragraph |
| 444 | `\color{red}` | Just before the threat-mapping table discussion |
| 484 | `\color{black}` | End of a paragraph following `\subsection{Scope of Privacy and Fairness Guarantees}` |
| 712 | `\color{red}` | Just before `\subsection{Formal NIZKP Statements}` |
| 1476 | `\color{red}` | Just before `\subsection{Secure Loan Processing}`'s first paragraph |
| 1705 | `\color{red}` | Just before `\section{Security Analysis}` |
| 1812 | `\color{black}` | Just before `\section{Evaluation Design and Analytical Assessment}` |
| 2452 | `\color{black}` | End of the Conclusion and Future Work section (redundant re-assertion; already black) |

No `\begin{...}`/`\end{...}` colour-scoping environment (e.g. no `color` package group environment) was used anywhere; every instance is a bare, unscoped `\color{...}` declaration. Because `\color` is a **declaration**, not a brace-scoped command, its effect persists from the point it is issued until the *next* `\color` command is issued, regardless of intervening `\section`/`\subsection` boundaries, `\begin{algorithm}`/`\end{algorithm}` blocks, or table floats. This is the root mechanism responsible for the leak.

---

## 2. Where colour state begins and ends (before repair)

Walking the nine commands in document order gives five colour *states*, not five pairs:

| Span | Start | End | Length | Balanced? |
|---|---|---|---|---|
| A | 164 (red) | 185 (black) | ~21 lines | Yes -- self-contained |
| (black, default) | 185 | 444 | -- | Yes |
| B | 444 (red) | 484 (black) | ~40 lines | Yes -- self-contained |
| (black, default) | 484 | 712 | -- | Yes |
| **C** | **712 (red)** | **1812 (black)** | **~1,100 lines** | **No -- three `\color{red}` calls (712, 1476, 1705) share one closing `\color{black}` (1812), with no colour change in between** |
| (black, default) | 1812 | 2452 | -- | Yes (2452's `\color{black}` is a harmless, redundant re-assertion of the already-active default) |

Spans A and B are correctly balanced pairs and were **not** touched by this repair. The single broken span, C, is the one the user's report and this audit both identify: because nothing resets colour between 712 and 1812, every line in that range -- roughly 1,100 lines, matching the user's estimate -- renders red in a compiled PDF, including the account/score/protected-attribute credential-issuance algorithms, the loan-application algorithm, the Secure Loan Processing algorithm (Algorithm 6), the compSim design section, the Secure Gender-Fairness Analysis section, Algorithm 7, and the entire Security Analysis section.

---

## 3. The command responsible for the leak

The leak has two independent causes, both within span C:

1. **No `\color{black}` (or closing brace) between the `\color{red}` at line 712 and the next colour command.** Whatever closed this span originally has been lost; the very next colour command found in the source is another `\color{red}` (line 1476), not a `\color{black}`.
2. **The same pattern repeats**: the `\color{red}` at line 1476 has no closing command before the next `\color{red}` at line 1705.

Only the *third* red declaration (1705) is properly closed, by the `\color{black}` at 1812.

---

## 4. Intended scope: what the evidence supports

Rather than guessing arbitrary boundaries, this audit used two firm, external anchors to determine intended scope: (a) the two already-correct pairs (A, B), which establish that the manuscript's actual convention is to bracket colouring around a *specific*, self-contained addition, not an entire multi-section span; and (b) Reviewer #2's own opening paragraph, which explicitly names the five things that "address my previous comments substantively":

> "The narrowed claims, the 'Scope of Privacy and Fairness Guarantees' subsection, the leakage profile, the collusion discussion and the formalised NIZKP relations address my previous comments substantively."

Mapping these five items against the document:

| Reviewer-credited item | Manuscript location | Falls within |
|---|---|---|
| "Scope of Privacy and Fairness Guarantees subsection" | `subsec:scope_guarantees` (~line 468) | Span B (444-484) -- already correct |
| "the formalised NIZKP relations" | `subsec:nizkp_formal`, "Formal NIZKP Statements" (~line 715) | Span C's *first* red call (712) |
| "the leakage profile" | Table `tab:leakage_profile`, "Adversarial Model and Leakage Profile" (~line 1720) | Span C's *third* red call (1705), inside `\section{Security Analysis}` |
| "the collusion discussion" | "Composition, Disclosure, and Collusion Limits" (~line 1782) | Same as above |
| "narrowed claims" | Theorem 1, "Protected-Attribute Confidentiality Claim" (~line 1763) | Same as above |

All five reviewer-credited items fall either inside the already-correct span B, or inside the *first* (712) or *third* (1705) red declaration of the broken span C. **None** of them fall inside the content between the *second* red declaration (1476, "Secure Loan Processing") and the third (1705) -- i.e. Algorithm 6, the compSim design section, and Secure Gender-Fairness Analysis.

This is corroborated independently by Reviewer #2's own Comment 1, which describes the compSim construction living in that exact span as something the reviewer is now *criticising* as degenerate -- which only makes sense if compSim was already present (not newly added) in the version Reviewer #2 reviewed. New, reviewer-praised content and reviewer-criticised pre-existing content cannot both be what a "here is what's new" highlight was marking.

**Conclusion on intended scope:**
- The `\color{red}` at line 712 was very likely intended to highlight only the "Formal NIZKP Statements" subsection (712 through just before `\subsection{Initialisation}`, ~line 1141) -- i.e. exactly the material the reviewer credits as "the formalised NIZKP relations."
- The `\color{red}` at line 1476 ("Secure Loan Processing") does **not** correspond to anything the reviewer credits as new, and independently corresponds to content the reviewer is currently criticising as pre-existing. It is treated as spurious/leaked, not as a second genuine highlight with its own lost closing tag.
- The `\color{red}` at line 1705 (`\section{Security Analysis}`), already correctly closed by the `\color{black}` at 1812, needed no boundary change -- it already, and correctly, brackets exactly the three remaining reviewer-credited items ("leakage profile," "collusion discussion," "narrowed claims"). This span was structurally fine on its own; it only appeared broken because it was preceded by leaked state from the unclosed 1476 span.

This reconstruction is offered as the best-supported reading of the evidence available, not as a certainty. See "What was not changed, and why" below for exactly how easy it is to revert or adjust if the authors know otherwise.

---

## 5. Exact repairs made

Four edits, all to `\color` declarations or their immediate replacement, plus one explanatory LaTeX comment. No other text was touched.

1. **Line 712**: `\color{red}` &rarr; `{\color{red}` (opens a properly brace-scoped group instead of an unscoped declaration).
2. **Line ~1138** (immediately after the `tab:nizkp_status` table's `\end{table*}`, immediately before `\subsection{Initialisation}`): inserted a closing `}` on its own line, closing the group opened in (1). This confines the red highlighting to exactly the "Formal NIZKP Statements" subsection (Setup/Prove/Verify definitions, the `tab:nizkp_constraints` and `tab:nizkp_status` tables, and the concrete-instantiation prose), consistent with the reviewer-credited "formalised NIZKP relations."
3. **Line 1476**: the bare `\color{red}` declaration was replaced with a seven-line LaTeX comment (`%`-prefixed, so it has zero effect on the compiled output) explaining exactly why it was judged spurious and pointing back to this file. The original text `\color{red}` is preserved verbatim inside the comment for anyone who wants to restore it exactly.
4. **Line 1705**: `\color{red}` &rarr; `{\color{red}` (opens a properly brace-scoped group).
5. **Line ~1818** (immediately after the paragraph ending "...discussed in the following sections.", immediately before `\section{Evaluation Design and Analytical Assessment}`): the bare `\color{black}` was replaced with a closing `}`, closing the group opened in (4). Because a closing brace reverts colour state to whatever was active before the group opened (default/black, since nothing colours the text immediately before line 1705), this is behaviourally identical to the original `\color{black}` for every line at and after this point -- no visual change here, only a structural one (declaration &rarr; scoped group).

**Untouched, and correct as-is:** the `\color{red}`/`\color{black}` pair at lines 164/185 and 444/484 (spans A and B); the `\color{black}` at line ~2458 (harmless, redundant re-assertion of the default colour, left in place since removing it has no effect and touching it is unnecessary risk for a formatting-only repair).

**Net effect on rendered colour, if compiled:**
- Still red: "Formal NIZKP Statements" (~426 lines, was already red, now properly scoped instead of leaking) and the whole "Security Analysis" section (~106 lines, was already red, now properly scoped instead of relying on leaked state from a prior span).
- **No longer red** (reverted to default/black): "Initialisation" through the end of "Secure Gender-Fairness Analysis" -- i.e. all credential-issuance algorithms, the loan-application algorithm, Algorithm 6 (Secure Loan Processing), the compSim design section, and Secure Gender-Fairness Analysis (~229 lines). This is the actual reduction that resolves the ~1,100-line complaint: total red is now approximately 426 + 106 = ~532 lines (still substantial, but the two coherent, reviewer-corroborated blocks only), down from the ~1,100-line leaked span.

---

## 6. Verification

- **Balanced braces**: overall curly-brace depth across the entire file returns to exactly 0 and never goes negative at any point (checked programmatically, character-by-character, ignoring `\{`/`\}` escapes).
- **Balanced environments**: every `\begin{env}`/`\end{env}` pair matches in count, for every environment name used in the document (checked programmatically).
- **No unintended colour-state leakage**: after the repair, exactly two `{\color{red} ... }` scoped groups remain (712-1141, 1705-1818), each independently self-closing; the two originally-correct bare pairs (164/185, 444/484) are unchanged; the spurious re-assertion at 1476 is neutralised via a comment, not left as live code; the harmless redundant `\color{black}` at ~2458 is untouched.
- **No unresolved cross-references**: every `\ref{...}` in the document still resolves to an existing `\label{...}` (checked programmatically; unaffected by this change, since no labels were touched).
- **No duplicate labels**: unaffected by this change (checked programmatically).
- **Balanced math delimiters**: inline `$...$` count is even and `\[`/`\]` display-math counts match (checked programmatically; unaffected by this change, since no math was touched).
- **`git diff manucript.tex`** was inspected line-by-line: the only changed lines are the four `\color` declarations described above, one seven-line explanatory comment insertion, and one incidental trailing-whitespace removal on the `\end{algorithmic}` line immediately preceding the Security Analysis section's colour command (a byte-level difference with **zero effect on compiled output** -- LaTeX treats trailing whitespace before a line break identically to no trailing whitespace). No word of prose, no numeral, no citation key, no algorithm step, no table cell, and no figure reference was added, removed, or reworded.

---

## 7. What was not changed, and why (and how to override)

- **Spans A and B (164/185, 444/484) were left untouched.** They are not part of "the issue" the user asked to be repaired (they are already correctly balanced), and touching working code in a formatting-only repair increases risk without benefit.
- **The redundant `\color{black}` at ~2458 was left untouched.** It is a harmless no-op (re-asserting a colour that is already active); removing it is unnecessary and was judged out of scope for this repair.
- **The judgement that line 1476's `\color{red}` was spurious, rather than a second genuine highlight whose own closing tag was separately lost, is a best-effort reconstruction, not a certainty.** It is well-supported (Reviewer #2's own words corroborate the boundary independently) but the authors may know the true original scope was different. If so, reverting is simple: restore `\color{red}` in place of the explanatory comment at line 1476 (the exact original text is preserved inside the comment), and decide where its own closing `\color{black}` (or a `}` if converted to a scoped group) should go.
- **Per item 5 of the task's instructions ("If revision colouring is no longer required for submission, do NOT remove it globally without documenting the proposed change"): this repair does not remove any colouring globally.** It narrows one specific, evidence-supported span and leaves two spans (Formal NIZKP Statements; Security Analysis) exactly as red as they were. If the authors decide, on reflection, that this highlighting convention (marking what was new in an earlier, pre-Reviewer#2 revision round) is no longer needed for the camera-ready submission at all, the clean way to remove it entirely is to delete both remaining `{\color{red} ... }` groups (including their braces) -- this is a one-step, easily reviewable follow-up change, deliberately not performed here since it was not asked for and is a distinct editorial decision from "fix the imbalance."

---

## 8. Confirmation: no scientific content changed

This repair touched only `\color` declarations, one LaTeX comment (which is invisible to the compiled document), and one whitespace-only byte (invisible to the compiled document). Specifically confirmed unchanged:
- Every equation, formula, and numerical value in the document.
- Every citation key and citation command.
- The full text of `reviewer2_response_draft.md`, `editor_revision_summary.md`, and `reviewer2_final_readiness.md` (not touched by this commit at all).
- Every algorithm's steps, every table's cells, and every figure reference.
- All prose wording, including the exact sentences immediately adjacent to every edited line.

This commit is intended to be reviewable and revertible independently of all scientific/content revisions in this repository's history.
