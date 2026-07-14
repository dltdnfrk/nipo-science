import type { UtcTimestamp } from "../common"

type TimestampParts = {
  readonly second: string
  readonly fraction: string
}

const timestampParts = (timestamp: UtcTimestamp): TimestampParts => {
  const withoutSuffix = timestamp.slice(0, -1)
  const separator = withoutSuffix.indexOf(".")
  const whole = separator === -1 ? withoutSuffix : withoutSuffix.slice(0, separator)
  return {
    second: whole.length === 16 ? `${whole}:00` : whole,
    fraction: separator === -1 ? "" : withoutSuffix.slice(separator + 1),
  }
}

export const compareUtcTimestamps = (left: UtcTimestamp, right: UtcTimestamp): number => {
  const leftParts = timestampParts(left)
  const rightParts = timestampParts(right)
  if (leftParts.second !== rightParts.second) {
    return leftParts.second < rightParts.second ? -1 : 1
  }
  const width = Math.max(leftParts.fraction.length, rightParts.fraction.length)
  const leftFraction = leftParts.fraction.padEnd(width, "0")
  const rightFraction = rightParts.fraction.padEnd(width, "0")
  if (leftFraction === rightFraction) return 0
  return leftFraction < rightFraction ? -1 : 1
}
