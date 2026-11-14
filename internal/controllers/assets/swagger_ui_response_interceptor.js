function (response) {
  try {
    if (response.ok && new URL(response.url, location.href).pathname.endsWith('/auth/logout')) {
      location.replace('/swagger/');
    }
  } catch (e) {}
  return response;
}
