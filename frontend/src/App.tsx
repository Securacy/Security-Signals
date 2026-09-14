import { useState } from "react";
import { getWidgetConfig } from "./widget/config";
import { Drawer } from "./widget/components/Drawer";
import "./widget/widget.css";

function App() {
  const [config] = useState(() => getWidgetConfig());
  return <Drawer apiBaseUrl={config.apiBaseUrl} parentOrigin={config.parentOrigin} />;
}

export default App;
