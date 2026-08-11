// Creates a new barber's login (Supabase Auth user) + their shop row in one call.
// Only callable by an account listed in `platform_admins` — checked below using the
// CALLER's own JWT (RLS-respecting client) before any privileged action runs.
// The service-role client (bypasses RLS) is only touched after that check passes.
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
    const { email, password, slug, shop_name } = await req.json();

    if (!email || !password || !slug || !shop_name) {
      return json({ error: "MISSING_FIELDS" }, 400);
    }
    if (!/^[a-z0-9-]{2,40}$/.test(slug)) {
      return json({ error: "INVALID_SLUG" }, 400);
    }
    if (String(password).length < 8) {
      return json({ error: "WEAK_PASSWORD" }, 400);
    }

    const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
    const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
    const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    // Client scoped to the caller's own JWT — RLS applies as normal.
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

    const { data: created, error: createErr } = await admin.auth.admin.createUser({
      email, password, email_confirm: true,
      user_metadata: { must_change_password: true },
    });
    if (createErr) return json({ error: "USER_CREATE_FAILED", detail: createErr.message }, 400);

    const { data: shop, error: shopErr } = await admin.from("shops").insert({
      owner_user_id: created.user.id, slug, shop_name,
    }).select().single();

    if (shopErr) {
      await admin.auth.admin.deleteUser(created.user.id); // rollback the orphaned auth user
      return json({ error: "SHOP_CREATE_FAILED", detail: shopErr.message }, 400);
    }

    return json({ ok: true, shop });
  } catch (e) {
    return json({ error: "SERVER_ERROR", detail: String(e) }, 500);
  }
});
