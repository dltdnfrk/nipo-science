import { expect, it } from "vitest"
import type { ReadonlyJsonArray, ReadonlyJsonObject, ReadonlyJsonValue } from "../src/common"
import { ProtocolRunEventSchema } from "../src/protocols/models"

const isReadonlyJsonObject = (value: ReadonlyJsonValue): value is ReadonlyJsonObject =>
  value !== null && typeof value === "object" && !Array.isArray(value)
const isReadonlyJsonArray = (value: ReadonlyJsonValue): value is ReadonlyJsonArray =>
  Array.isArray(value)

it("deep-freezes RunEvent data without changing its JSON representation", () => {
  // Given: mutable nested JSON accepted at the RunEvent boundary.
  const source = { analysis: [{ message: "measured" }] }
  const event = ProtocolRunEventSchema.parse({
    run_id: "018f47a0-7b9c-7abe-8def-0123456789ab",
    sequence: 1,
    kind: "run.status",
    data: source,
    created_at: "2026-07-13T10:00:00Z",
  })
  const serialized = JSON.stringify(event)
  const data = event.data
  expect(isReadonlyJsonObject(data)).toBe(true)
  if (!isReadonlyJsonObject(data)) return
  const analysisKey = "analysis"
  const analysis = data[analysisKey]
  expect(analysis === undefined ? false : isReadonlyJsonArray(analysis)).toBe(true)
  if (analysis === undefined || !isReadonlyJsonArray(analysis)) return
  const record = analysis[0]
  expect(record === undefined ? false : isReadonlyJsonObject(record)).toBe(true)
  if (record === undefined || !isReadonlyJsonObject(record)) return

  // When: both the source and accepted nested record are attacked after validation.
  const sourceRecord = source.analysis[0]
  if (sourceRecord === undefined) return
  expect(Reflect.set(sourceRecord, "Authorization", `Bearer ${"x".repeat(24)}`)).toBe(true)

  // Then: mutation is impossible and the validated wire representation is unchanged.
  expect(Object.isFrozen(data)).toBe(true)
  expect(Object.isFrozen(analysis)).toBe(true)
  expect(Object.isFrozen(record)).toBe(true)
  expect(Reflect.set(record, "Authorization", `Bearer ${"x".repeat(24)}`)).toBe(false)
  expect(JSON.stringify(event)).toBe(serialized)
  expect(ProtocolRunEventSchema.parse(JSON.parse(serialized))).toEqual(event)
})
