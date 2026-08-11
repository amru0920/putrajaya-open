// Permanently deletes a shop: its bookings, day_config rows, the shop row
// itself, and the barber's login (auth.users). Irreversible.
// Only callable by an account listed in `platform_admins` — checked below using
// the CALLER's own JWT (RLS-respecting client) before any privileged action runs.
import { createClient } from "npm:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  try {
    const { shop_id } = await req.json();
    if (!shop_id) return json({ error: "MISSING_FIELDS" }, 400);

    const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
    const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
    const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    const authHeader = req.headers.get("Authorization") ?? "";
    const callerClient = createClient(SUPABASE_URL, ANON_KEY, {
      global: { headers: { Authorization: authHeader } },
    });

    const { data: { user } } = await callerClient.auth.getUser();
    if (!user) return json({ error: "UNAUTHORIZED" }, 401);

    const { data: adminRow } = await callerClient
      .from("platform_admins").select("user_id").eq("user_id", user.id).maybeSingle();
    if (!adminRow) return json({ error: "UNAUTHORIZED" }, 403);

    // Only past this point do we touch the elevated service-role client.
    const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

    const { data: shop, error: findErr } = await admin
      .from("shops").select("id, owner_user_id, shop_name").eq("id", shop_id).maybeSingle();
    if (findErr || !shop) return json({ error: "SHOP_NOT_FOUND" }, 404);

    // Order matters: children before the shop row, shop row before the auth user
    // (owner_user_id has no ON DELETE CASCADE, so the FK blocks deleting the user first).
    await admin.from("bookings").delete().eq("shop_id", shop_id);
    await admin.from("day_config").delete().eq("shop_id", shop_id);

    const { error: shopDelErr } = await admin.from("shops").delete().eq("id", shop_id);
    if (shopDelErr) return json({ error: "SHOP_DELETE_FAILED", detail: shopDelErr.message }, 400);

    await admin.auth.admin.deleteUser(shop.owner_user_id);

    return json({ ok: true });
  } catch (e) {
    return json({ error: "SERVER_ERROR", detail: String(e) }, 500);
  }
});
