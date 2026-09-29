/** Time-of-day greeting, using the VIEWER's own local clock (not the
 * server's) - this is a client-rendered header, so the person reading it
 * cares what time it is where they are. */
export function timeOfDayGreeting(now: Date = new Date()): string {
  const hour = now.getHours();
  if (hour < 5) return "Good evening";
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}
