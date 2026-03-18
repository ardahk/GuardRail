export default function TypingIndicator() {
  return (
    <div className="flex items-center gap-1 px-1 py-2">
      <span className="h-2 w-2 rounded-full bg-[#8B7B6E] animate-bounce [animation-delay:0ms]" />
      <span className="h-2 w-2 rounded-full bg-[#8B7B6E] animate-bounce [animation-delay:150ms]" />
      <span className="h-2 w-2 rounded-full bg-[#8B7B6E] animate-bounce [animation-delay:300ms]" />
    </div>
  );
}
