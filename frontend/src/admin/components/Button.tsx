import { forwardRef, type ButtonHTMLAttributes } from "react";

type Variant = "primary" | "secondary" | "danger" | "ghost";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", className, type = "button", ...rest },
  ref,
) {
  const classes = ["adm-btn", `adm-btn--${variant}`, className].filter(Boolean).join(" ");
  return <button ref={ref} type={type} className={classes} {...rest} />;
});
