import { Input } from "@heroui/input";

export default function Home() {
  return (
    <section className="flex gap-3 flex-col items-center justify-center w-full">
      <h1 className="text-4xl font-bold">Pass-Tee-Port Checker</h1>
	  <Input label="Email" placeholder="Enter your email" type="email" className="w-full max-w-md" />
    </section>
  );
}
